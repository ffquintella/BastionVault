//! Native FIDO2/CTAP2 support for Tauri.
//!
//! Bypasses the browser `navigator.credentials` API by talking directly to
//! USB security keys via the Mozilla `authenticator` crate, then submitting
//! the result to the vault backend in the same JSON format that webauthn-rs
//! expects.

use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

use authenticator::authenticatorservice::AuthenticatorService;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
    ResidentKeyRequirement, Transport, UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use authenticator::{Pin, StatusPinUv, StatusUpdate};
use authenticator::authenticatorservice::{RegisterArgs, SignArgs};
use base64urlsafedata::Base64UrlSafeData;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, State};

use crate::commands::fido2::{Fido2LoginResponse, make_request};
use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

// ── Helpers ──────────────────────────────────────────────────────────

/// The `clientDataJSON` structure as defined by the WebAuthn spec.
/// webauthn-rs validates the SHA-256 hash of these raw bytes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
}

fn build_client_data_json(ceremony: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
    let cd = CollectedClientData {
        type_: ceremony.to_string(),
        challenge: challenge_b64url.to_string(),
        origin: origin.to_string(),
        cross_origin: false,
    };
    serde_json::to_vec(&cd).expect("CollectedClientData serialization cannot fail")
}

fn base64url_encode(data: &[u8]) -> String {
    use base64urlsafedata::Base64UrlSafeData;
    // Base64UrlSafeData serializes with serde, but we just need the string
    let b = Base64UrlSafeData::from(data.to_vec());
    // Use the Display impl which gives base64url without padding
    let json = serde_json::to_string(&b).unwrap();
    // serde serializes it as a quoted string, strip the quotes
    json.trim_matches('"').to_string()
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, CommandError> {
    // Handle both padded and unpadded base64url
    let b: Base64UrlSafeData = serde_json::from_value(Value::String(s.to_string()))
        .map_err(|e| CommandError::from(format!("base64url decode error: {e}")))?;
    Ok(b.into())
}

/// Read the FIDO2 relying party config from the vault.
async fn read_fido2_config(state: &State<'_, AppState>) -> Result<(String, String, String), CommandError> {
    use bastion_vault::logical::{Operation, Request};

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = Operation::Read;
    req.path = "auth/userpass/fido2/config".to_string();
    req.client_token = token;

    let resp = core.handle_request(&mut req).await.map_err(CommandError::from)?;
    let data = resp
        .and_then(|r| r.data)
        .ok_or("FIDO2 not configured")?;

    let rp_id = data.get("rp_id").and_then(|v| v.as_str()).unwrap_or("localhost").to_string();
    let rp_origin = data.get("rp_origin").and_then(|v| v.as_str()).unwrap_or("https://localhost").to_string();
    let rp_name = data.get("rp_name").and_then(|v| v.as_str()).unwrap_or("BastionVault").to_string();
    Ok((rp_id, rp_origin, rp_name))
}

fn parse_cose_alg(alg: i64) -> authenticator::crypto::COSEAlgorithm {
    match alg {
        -7 => authenticator::crypto::COSEAlgorithm::ES256,
        -257 => authenticator::crypto::COSEAlgorithm::RS256,
        -37 => authenticator::crypto::COSEAlgorithm::PS256,
        -8 => authenticator::crypto::COSEAlgorithm::EDDSA,
        // Default to ES256 for unknown algorithms
        _ => authenticator::crypto::COSEAlgorithm::ES256,
    }
}

fn parse_uv_requirement(s: &str) -> UserVerificationRequirement {
    match s {
        "required" => UserVerificationRequirement::Required,
        "discouraged" => UserVerificationRequirement::Discouraged,
        _ => UserVerificationRequirement::Preferred,
    }
}

/// Collect a PIN from the frontend by emitting a request event, then waiting
/// for the `fido2_submit_pin` Tauri command to relay the user's input.
///
/// Returns `Some(pin_string)` or `None` if the user cancelled / timed out.
fn request_pin_from_frontend(
    handle: &AppHandle,
    pin_rx: &std::sync::mpsc::Receiver<String>,
    event_payload: &str,
) -> Option<String> {
    let _ = handle.emit("fido2-pin-request", event_payload);
    // Wait up to 2 minutes for the user to enter their PIN
    match pin_rx.recv_timeout(Duration::from_secs(120)) {
        Ok(pin) if pin.is_empty() => None, // user cancelled
        Ok(pin) => Some(pin),
        Err(_) => None,
    }
}

/// Handle all `StatusUpdate` variants, including interactive PIN collection.
/// `pin_rx` is the receiving end of a channel whose sender is held in `AppState.pin_sender`.
fn handle_status_updates(
    status_rx: std::sync::mpsc::Receiver<StatusUpdate>,
    handle: AppHandle,
    pin_rx: std::sync::mpsc::Receiver<String>,
) {
    while let Ok(status) = status_rx.recv() {
        match status {
            StatusUpdate::PresenceRequired => {
                let _ = handle.emit("fido2-status", "tap-key");
            }
            StatusUpdate::SelectDeviceNotice => {
                let _ = handle.emit("fido2-status", "select-device");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                let _ = handle.emit("fido2-status", "pin-required");
                if let Some(pin) = request_pin_from_frontend(&handle, &pin_rx, "pin-required") {
                    let _ = sender.send(Pin::new(&pin));
                } else {
                    // User cancelled — drop the sender which will abort the ceremony
                    drop(sender);
                }
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
                let msg = attempts
                    .map(|a| format!("invalid-pin:{a}"))
                    .unwrap_or_else(|| "invalid-pin".to_string());
                let _ = handle.emit("fido2-status", &msg);
                if let Some(pin) = request_pin_from_frontend(&handle, &pin_rx, &msg) {
                    let _ = sender.send(Pin::new(&pin));
                } else {
                    drop(sender);
                }
            }
            StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
                let _ = handle.emit("fido2-status", "pin-auth-blocked");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
                let _ = handle.emit("fido2-status", "pin-blocked");
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts)) => {
                let msg = attempts
                    .map(|a| format!("invalid-uv:{a}"))
                    .unwrap_or_else(|| "invalid-uv".to_string());
                let _ = handle.emit("fido2-status", &msg);
            }
            StatusUpdate::PinUvError(StatusPinUv::UvBlocked) => {
                let _ = handle.emit("fido2-status", "uv-blocked");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinNotSet) => {
                let _ = handle.emit("fido2-status", "pin-not-set");
            }
            StatusUpdate::PinUvError(e) => {
                let _ = handle.emit("fido2-status", format!("pin-error: {e:?}"));
            }
            _ => {}
        }
    }
}

// ── PIN submission command ───────────────────────────────────────────

#[tauri::command]
pub async fn fido2_submit_pin(
    pin: String,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let sender = state.pin_sender.lock().unwrap().take();
    if let Some(tx) = sender {
        tx.send(pin).map_err(|_| CommandError::from("PIN channel closed"))?;
    }
    Ok(())
}

// ── Registration ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn fido2_native_register(
    username: String,
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> CmdResult<()> {
    // 1. Read FIDO2 config
    let (rp_id, rp_origin, rp_name) = read_fido2_config(&state).await?;

    // 2. Call register/begin to get challenge
    let mut body = Map::new();
    body.insert("username".to_string(), Value::String(username.clone()));

    let resp = make_request(
        &state,
        bastion_vault::logical::Operation::Write,
        "auth/userpass/fido2/register/begin".to_string(),
        Some(body),
    ).await?;

    let data = resp
        .and_then(|r| r.data)
        .ok_or("No challenge data returned")?;

    // 3. Parse the CreationChallengeResponse
    let data_value = Value::Object(data.clone());
    let public_key = data.get("publicKey").unwrap_or(&data_value);

    let challenge_b64 = public_key.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("Missing challenge in response")?;
    let _challenge_bytes = base64url_decode(challenge_b64)?;

    // Parse user
    let user_obj = public_key.get("user").ok_or("Missing user in response")?;
    let user_id_b64 = user_obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let user_id = base64url_decode(user_id_b64)?;
    let user_name = user_obj.get("name").and_then(|v| v.as_str()).unwrap_or(&username);
    let user_display = user_obj.get("displayName").and_then(|v| v.as_str()).unwrap_or(user_name);

    // Parse pubKeyCredParams
    let pub_cred_params: Vec<PublicKeyCredentialParameters> = public_key
        .get("pubKeyCredParams")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("alg").and_then(|a| a.as_i64()))
                .map(|alg| PublicKeyCredentialParameters { alg: parse_cose_alg(alg) })
                .collect()
        })
        .unwrap_or_else(|| vec![
            PublicKeyCredentialParameters { alg: authenticator::crypto::COSEAlgorithm::ES256 },
        ]);

    // Parse excludeCredentials
    let exclude_list: Vec<PublicKeyCredentialDescriptor> = public_key
        .get("excludeCredentials")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("id").and_then(|v| v.as_str())?;
                    Some(PublicKeyCredentialDescriptor {
                        id: base64url_decode(id).ok()?,
                        transports: vec![Transport::USB],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse authenticatorSelection
    let auth_sel = public_key.get("authenticatorSelection");
    let uv_req = auth_sel
        .and_then(|s| s.get("userVerification"))
        .and_then(|v| v.as_str())
        .unwrap_or("preferred");
    let rk_req = auth_sel
        .and_then(|s| s.get("residentKey"))
        .and_then(|v| v.as_str())
        .unwrap_or("discouraged");

    let resident_key_req = match rk_req {
        "required" => ResidentKeyRequirement::Required,
        "preferred" => ResidentKeyRequirement::Preferred,
        _ => ResidentKeyRequirement::Discouraged,
    };

    // 4. Build clientDataJSON and hash
    let client_data_json = build_client_data_json("webauthn.create", challenge_b64, &rp_origin);
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();

    // 5. Build RegisterArgs
    let register_args = RegisterArgs {
        client_data_hash,
        relying_party: RelyingParty {
            id: rp_id.clone(),
            name: Some(rp_name),
        },
        origin: rp_origin.clone(),
        user: PublicKeyCredentialUserEntity {
            id: user_id,
            name: Some(user_name.to_string()),
            display_name: Some(user_display.to_string()),
        },
        pub_cred_params,
        exclude_list,
        user_verification_req: parse_uv_requirement(uv_req),
        resident_key_req,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    // 6. Run authenticator ceremony in blocking thread
    let timeout_ms = public_key.get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(60000);

    // Set up the PIN communication channel
    let (pin_tx, pin_rx) = channel::<String>();
    {
        let mut guard = state.pin_sender.lock().unwrap();
        *guard = Some(pin_tx);
    }

    let handle = app_handle.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut service = AuthenticatorService::new()
            .map_err(|e| CommandError::from(format!("Failed to init authenticator: {e:?}")))?;
        service.add_detected_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (result_tx, result_rx) = channel();

        // Status update thread with full PIN handling
        let handle_clone = handle.clone();
        std::thread::spawn(move || {
            handle_status_updates(status_rx, handle_clone, pin_rx);
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = result_tx.send(rv);
        }));

        let _ = handle.emit("fido2-status", "insert-key");

        service.register(timeout_ms, register_args, status_tx, callback)
            .map_err(|e| CommandError::from(e))?;

        match result_rx.recv_timeout(Duration::from_millis(timeout_ms + 5000)) {
            Ok(Ok(register_result)) => Ok(register_result),
            Ok(Err(e)) => Err(CommandError::from(e)),
            Err(RecvTimeoutError::Timeout) => Err(CommandError::from("Registration timed out")),
            Err(e) => Err(CommandError::from(format!("Registration channel error: {e}"))),
        }
    })
    .await
    .map_err(|e| CommandError::from(format!("Task join error: {e}")))??;

    // Clean up PIN channel
    let _ = state.pin_sender.lock().unwrap().take();

    let _ = app_handle.emit("fido2-status", "processing");

    // 7. Construct RegisterPublicKeyCredential for webauthn-rs
    let att_obj_cbor = serde_cbor::to_vec(&result.att_obj)
        .map_err(|e| CommandError::from(format!("CBOR serialize error: {e}")))?;

    let cred_id = result.att_obj.auth_data.credential_data
        .as_ref()
        .map(|cd| cd.credential_id.clone())
        .unwrap_or_default();

    let cred_id_b64 = base64url_encode(&cred_id);

    let credential_json = serde_json::json!({
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "response": {
            "attestationObject": base64url_encode(&att_obj_cbor),
            "clientDataJSON": base64url_encode(&client_data_json),
        },
        "extensions": {}
    });

    // 8. Send to register/complete
    let mut body = Map::new();
    body.insert("username".to_string(), Value::String(username));
    body.insert("credential".to_string(), Value::String(credential_json.to_string()));

    make_request(
        &state,
        bastion_vault::logical::Operation::Write,
        "auth/userpass/fido2/register/complete".to_string(),
        Some(body),
    ).await?;

    let _ = app_handle.emit("fido2-status", "complete");
    Ok(())
}

// ── Authentication ───────────────────────────────────────────────────

#[tauri::command]
pub async fn fido2_native_login(
    username: String,
    state: State<'_, AppState>,
    app_handle: AppHandle,
) -> CmdResult<Fido2LoginResponse> {
    // 1. Read FIDO2 config
    let (_rp_id, rp_origin, _rp_name) = read_fido2_config(&state).await?;

    // 2. Call login/begin to get challenge
    let mut body = Map::new();
    body.insert("username".to_string(), Value::String(username.clone()));

    let resp = make_request(
        &state,
        bastion_vault::logical::Operation::Write,
        "auth/userpass/fido2/login/begin".to_string(),
        Some(body),
    ).await?;

    let data = resp
        .and_then(|r| r.data)
        .ok_or("No challenge data returned")?;

    // 3. Parse RequestChallengeResponse
    let data_value = Value::Object(data.clone());
    let public_key = data.get("publicKey").unwrap_or(&data_value);

    let challenge_b64 = public_key.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or("Missing challenge in response")?;

    let rp_id = public_key.get("rpId")
        .and_then(|v| v.as_str())
        .unwrap_or(&_rp_id);

    // Parse allowCredentials
    let allow_list: Vec<PublicKeyCredentialDescriptor> = public_key
        .get("allowCredentials")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("id").and_then(|v| v.as_str())?;
                    Some(PublicKeyCredentialDescriptor {
                        id: base64url_decode(id).ok()?,
                        transports: vec![Transport::USB],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let uv_req = public_key.get("userVerification")
        .and_then(|v| v.as_str())
        .unwrap_or("preferred");

    // 4. Build clientDataJSON and hash
    let client_data_json = build_client_data_json("webauthn.get", challenge_b64, &rp_origin);
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();

    // 5. Build SignArgs
    let sign_args = SignArgs {
        client_data_hash,
        origin: rp_origin.clone(),
        relying_party_id: rp_id.to_string(),
        allow_list,
        user_verification_req: parse_uv_requirement(uv_req),
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let timeout_ms = public_key.get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(60000);

    // Set up PIN communication channel
    let (pin_tx, pin_rx) = channel::<String>();
    {
        let mut guard = state.pin_sender.lock().unwrap();
        *guard = Some(pin_tx);
    }

    // 6. Run authenticator ceremony
    let handle = app_handle.clone();
    let sign_result = tokio::task::spawn_blocking(move || {
        let mut service = AuthenticatorService::new()
            .map_err(|e| CommandError::from(format!("Failed to init authenticator: {e:?}")))?;
        service.add_detected_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (result_tx, result_rx) = channel();

        // Status update thread with full PIN handling
        let handle_clone = handle.clone();
        std::thread::spawn(move || {
            handle_status_updates(status_rx, handle_clone, pin_rx);
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = result_tx.send(rv);
        }));

        let _ = handle.emit("fido2-status", "insert-key");

        service.sign(timeout_ms, sign_args, status_tx, callback)
            .map_err(|e| CommandError::from(e))?;

        match result_rx.recv_timeout(Duration::from_millis(timeout_ms + 5000)) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(CommandError::from(e)),
            Err(RecvTimeoutError::Timeout) => Err(CommandError::from("Authentication timed out")),
            Err(e) => Err(CommandError::from(format!("Authentication channel error: {e}"))),
        }
    })
    .await
    .map_err(|e| CommandError::from(format!("Task join error: {e}")))??;

    // Clean up PIN channel
    let _ = state.pin_sender.lock().unwrap().take();

    let _ = app_handle.emit("fido2-status", "processing");

    // 7. Construct PublicKeyCredential for webauthn-rs
    let assertion = &sign_result.assertion;
    let cred_id = assertion.credentials
        .as_ref()
        .map(|c| c.id.clone())
        .unwrap_or_default();
    let cred_id_b64 = base64url_encode(&cred_id);

    let auth_data_bytes = assertion.auth_data.to_vec();
    let user_handle = assertion.user
        .as_ref()
        .map(|u| base64url_encode(&u.id));

    let mut response_obj = serde_json::json!({
        "authenticatorData": base64url_encode(&auth_data_bytes),
        "clientDataJSON": base64url_encode(&client_data_json),
        "signature": base64url_encode(&assertion.signature),
    });

    if let Some(uh) = user_handle {
        response_obj.as_object_mut().unwrap().insert("userHandle".to_string(), Value::String(uh));
    }

    let credential_json = serde_json::json!({
        "id": cred_id_b64,
        "rawId": cred_id_b64,
        "type": "public-key",
        "response": response_obj,
        "extensions": {}
    });

    // 8. Send to login/complete
    let mut body = Map::new();
    body.insert("username".to_string(), Value::String(username));
    body.insert("credential".to_string(), Value::String(credential_json.to_string()));

    let resp = make_request(
        &state,
        bastion_vault::logical::Operation::Write,
        "auth/userpass/fido2/login/complete".to_string(),
        Some(body),
    ).await?;

    // 9. Extract token and policies from auth response
    match resp {
        Some(r) => {
            if let Some(auth) = r.auth {
                let token = auth.client_token.clone();
                // Store token in state
                *state.token.lock().await = Some(token.clone());
                let _ = app_handle.emit("fido2-status", "complete");
                Ok(Fido2LoginResponse {
                    token,
                    policies: auth.policies.clone(),
                })
            } else {
                Err("Login failed: no auth in response".into())
            }
        }
        None => Err("Login failed: empty response".into()),
    }
}
