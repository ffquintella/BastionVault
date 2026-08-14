//! Wire-format types for browser ↔ server WebAuthn JSON payloads.
//!
//! Field names follow the W3C WebAuthn IDL (camelCase). Binary fields
//! are carried as base64url-no-pad strings; the server decodes them
//! when needed.

use serde::{Deserialize, Serialize};

// =================================================================
// Registration challenge (server → browser)
// =================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationChallengeResponse {
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RpEntity,
    pub user: UserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ExcludeCredential>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpEntity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    /// base64url-encoded user handle.
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub ty: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludeCredential {
    #[serde(rename = "type")]
    pub ty: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
}

// =================================================================
// Registration response (browser → server)
// =================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialAttestation {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type", default = "public_key_type")]
    pub ty: String,
    pub response: AuthenticatorAttestationResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    // WebAuthn spec name is `clientDataJSON` (capital JSON). Serde's
    // camelCase auto-rename would produce `clientDataJson`, which would
    // reject every spec-compliant client (browsers + the native
    // authenticator). Pin the rename to the spec name; keep the old
    // camelCase form as a deserialization alias for legacy callers.
    #[serde(rename = "clientDataJSON", alias = "clientDataJson")]
    pub client_data_json: String,
    pub attestation_object: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

// =================================================================
// Authentication challenge (server → browser)
// =================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationChallengeResponse {
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub ty: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

// =================================================================
// Authentication response (browser → server)
// =================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialAssertion {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type", default = "public_key_type")]
    pub ty: String,
    pub response: AuthenticatorAssertionResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    // See `AuthenticatorAttestationResponse::client_data_json` for the
    // rationale on the spec-name pin + legacy alias.
    #[serde(rename = "clientDataJSON", alias = "clientDataJson")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

fn public_key_type() -> String {
    "public-key".to_string()
}
