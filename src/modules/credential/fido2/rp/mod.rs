//! Pure-Rust WebAuthn Relying Party.
//!
//! Replaces the `webauthn-rs` crate, which transitively pulled OpenSSL via
//! `webauthn-attestation-ca`. This implementation only handles the subset
//! of WebAuthn we actually use: passkey registration / authentication with
//! attestation format `none`. ES256 and Ed25519 (EdDSA) signatures are
//! supported — together those cover every passkey-capable authenticator
//! in practice.
//!
//! See `path_register.rs` and `path_login.rs` for the HTTP wiring.

mod auth_data;
pub(crate) mod b64;
mod challenge;
mod client_data;
mod cose;
mod errors;
mod proto;
mod verify;

#[cfg(test)]
mod tests;

pub use challenge::Challenge;
pub use errors::RpError;
pub use proto::{
    AllowCredential, AuthenticationChallengeResponse, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorSelection, ExcludeCredential,
    PubKeyCredParams, PublicKeyCredentialAssertion, PublicKeyCredentialAttestation,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegistrationChallengeResponse, RpEntity, UserEntity,
};

use serde::{Deserialize, Serialize};

use self::b64 as base64url;

/// A registered passkey credential, stored alongside its owning user.
///
/// Binary fields (`cred_id`, `cose_pub_key`, `user_handle`) are stored
/// as base64url-no-pad strings so the on-disk JSON is human-readable
/// and stable across serde-version bumps. They're decoded to raw bytes
/// only at use time inside the `RelyingParty` methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    /// Storage version. Bump when the on-disk shape changes.
    #[serde(default = "default_version")]
    pub v: u32,
    /// Credential ID, base64url-no-pad.
    pub cred_id: String,
    /// Raw COSE_Key CBOR bytes, base64url-no-pad.
    pub cose_pub_key: String,
    /// Last seen sign counter. Compared monotonically to detect cloning.
    pub sign_count: u32,
    /// Authenticator-supplied user handle, base64url-no-pad.
    /// Typically a 16-byte UUID.
    #[serde(default)]
    pub user_handle: String,
    /// Optional list of transports advertised by the client during
    /// registration (e.g. `["usb", "nfc"]`). Used to populate
    /// `allowCredentials.transports` on subsequent auth challenges.
    #[serde(default)]
    pub transports: Vec<String>,
    /// Unix epoch seconds at registration time.
    pub created_at: i64,
}

fn default_version() -> u32 {
    1
}

impl Passkey {
    /// Decode `cred_id` to raw bytes.
    pub fn cred_id_bytes(&self) -> Result<Vec<u8>, RpError> {
        base64url::decode(&self.cred_id)
            .map_err(|e| RpError::Decode(format!("stored cred_id base64: {e}")))
    }

    /// Decode the stored COSE public key bytes.
    pub fn cose_pub_key_bytes(&self) -> Result<Vec<u8>, RpError> {
        base64url::decode(&self.cose_pub_key)
            .map_err(|e| RpError::Decode(format!("stored cose_pub_key base64: {e}")))
    }

    /// Construct an `AllowCredential` referencing this passkey for an
    /// authentication challenge.
    pub fn to_allow_credential(&self) -> AllowCredential {
        AllowCredential {
            ty: "public-key".to_string(),
            id: self.cred_id.clone(),
            transports: if self.transports.is_empty() {
                None
            } else {
                Some(self.transports.clone())
            },
        }
    }
}

/// Result of a successful authentication: the credential that was used
/// and the new sign counter the authenticator reported. The caller is
/// responsible for persisting `new_sign_count` back to the matched
/// passkey.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub cred_id: Vec<u8>,
    pub new_sign_count: u32,
}

/// Server-side state held between `begin_registration` and
/// `finish_registration` calls. Persisted per-username during the
/// ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub challenge: Challenge,
    /// Stable user handle, base64url-no-pad.
    pub user_handle: String,
    pub username: String,
}

/// Server-side state held between `begin_authentication` and
/// `finish_authentication` calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub challenge: Challenge,
    /// Credential IDs that were offered to the client (base64url).
    pub allow_cred_ids: Vec<String>,
}

/// Configured Relying Party identity. Cheap to construct per request.
#[derive(Debug, Clone)]
pub struct RelyingParty<'a> {
    pub rp_id: &'a str,
    pub rp_origin: &'a str,
    pub rp_name: &'a str,
}

impl<'a> RelyingParty<'a> {
    /// Validate that `rp_origin` is a parseable URL and (loosely) that
    /// `rp_id` is a registrable suffix of its host.
    pub fn validate(&self) -> Result<(), RpError> {
        let url = url::Url::parse(self.rp_origin)
            .map_err(|e| RpError::InvalidConfig(format!("invalid rp_origin: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| RpError::InvalidConfig("rp_origin has no host".into()))?;
        if host != self.rp_id && !host.ends_with(&format!(".{}", self.rp_id)) {
            return Err(RpError::InvalidConfig(format!(
                "rp_id `{}` is not a registrable suffix of origin host `{}`",
                self.rp_id, host
            )));
        }
        Ok(())
    }

    /// Begin a passkey registration ceremony.
    pub fn begin_registration(
        &self,
        username: &str,
        display_name: &str,
        user_handle: [u8; 16],
        exclude: &[Vec<u8>],
    ) -> Result<(RegistrationChallengeResponse, RegistrationState), RpError> {
        self.validate()?;
        let challenge = Challenge::random();
        let exclude_credentials = if exclude.is_empty() {
            None
        } else {
            Some(
                exclude
                    .iter()
                    .map(|id| ExcludeCredential {
                        ty: "public-key".to_string(),
                        id: base64url::encode(id),
                    })
                    .collect(),
            )
        };

        let resp = RegistrationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                rp: RpEntity {
                    id: self.rp_id.to_string(),
                    name: self.rp_name.to_string(),
                },
                user: UserEntity {
                    id: base64url::encode(&user_handle),
                    name: username.to_string(),
                    display_name: display_name.to_string(),
                },
                challenge: challenge.b64.clone(),
                pub_key_cred_params: vec![
                    PubKeyCredParams { ty: "public-key".to_string(), alg: -7 }, // ES256
                    PubKeyCredParams { ty: "public-key".to_string(), alg: -8 }, // EdDSA
                ],
                timeout: Some(60_000),
                attestation: Some("none".to_string()),
                exclude_credentials,
                authenticator_selection: Some(AuthenticatorSelection {
                    resident_key: Some("preferred".to_string()),
                    user_verification: Some("preferred".to_string()),
                    require_resident_key: None,
                    authenticator_attachment: None,
                }),
            },
        };

        let state = RegistrationState {
            challenge,
            user_handle: base64url::encode(&user_handle),
            username: username.to_string(),
        };

        Ok((resp, state))
    }

    /// Verify a registration response; on success returns the new
    /// `Passkey` for the caller to persist.
    pub fn finish_registration(
        &self,
        attestation: &PublicKeyCredentialAttestation,
        state: &RegistrationState,
    ) -> Result<Passkey, RpError> {
        self.validate()?;

        // 1. clientDataJSON.
        let client_data_bytes = base64url::decode(&attestation.response.client_data_json)
            .map_err(|e| RpError::Decode(format!("clientDataJSON base64: {e}")))?;
        client_data::verify(
            &client_data_bytes,
            "webauthn.create",
            self.rp_origin,
            &state.challenge,
        )?;

        // 2. attestationObject.
        let attest_bytes = base64url::decode(&attestation.response.attestation_object)
            .map_err(|e| RpError::Decode(format!("attestationObject base64: {e}")))?;
        let attest = auth_data::AttestationObject::parse(&attest_bytes)?;
        if attest.fmt != "none" {
            return Err(RpError::UnsupportedAttestation(attest.fmt));
        }

        // 3. authenticatorData inside the attestation.
        let auth_data = auth_data::AuthenticatorData::parse(&attest.auth_data)?;
        auth_data.expect_rp_id(self.rp_id)?;
        if !auth_data.flags.user_present() {
            return Err(RpError::UserPresenceMissing);
        }
        if !auth_data.flags.attested_credential_data() {
            return Err(RpError::MissingAttestedCredentialData);
        }
        let cred = auth_data
            .attested_credential
            .as_ref()
            .ok_or(RpError::MissingAttestedCredentialData)?;

        // 4. Sanity-check the COSE key parses now so we don't store garbage.
        cose::parse_public_key(&cred.cose_public_key)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Ok(Passkey {
            v: 1,
            cred_id: base64url::encode(&cred.credential_id),
            cose_pub_key: base64url::encode(&cred.cose_public_key),
            sign_count: auth_data.sign_count,
            user_handle: state.user_handle.clone(),
            transports: attestation
                .response
                .transports
                .clone()
                .unwrap_or_default(),
            created_at: now,
        })
    }

    /// Begin a passkey authentication ceremony.
    pub fn begin_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> Result<(AuthenticationChallengeResponse, AuthenticationState), RpError> {
        self.validate()?;
        if passkeys.is_empty() {
            return Err(RpError::NoCredentials);
        }
        let challenge = Challenge::random();
        let allow_credentials: Vec<AllowCredential> =
            passkeys.iter().map(Passkey::to_allow_credential).collect();
        let allow_cred_ids: Vec<String> =
            passkeys.iter().map(|p| p.cred_id.clone()).collect();

        let resp = AuthenticationChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.b64.clone(),
                timeout: Some(60_000),
                rp_id: self.rp_id.to_string(),
                allow_credentials,
                user_verification: Some("preferred".to_string()),
            },
        };

        Ok((
            resp,
            AuthenticationState {
                challenge,
                allow_cred_ids,
            },
        ))
    }

    /// Verify an authentication assertion. On success returns the
    /// matched credential ID and the new sign counter.
    pub fn finish_authentication(
        &self,
        assertion: &PublicKeyCredentialAssertion,
        state: &AuthenticationState,
        passkeys: &[Passkey],
    ) -> Result<AuthResult, RpError> {
        self.validate()?;

        // 1. Match cred_id against the offered allow-list and the user's stored
        // passkeys. We do both checks: the allow-list rules out cross-user
        // confusion if multiple users share a backend.
        if !state.allow_cred_ids.iter().any(|id| id == &assertion.raw_id) {
            return Err(RpError::UnknownCredential);
        }
        let raw_id = base64url::decode(&assertion.raw_id)
            .map_err(|e| RpError::Decode(format!("rawId base64: {e}")))?;
        let pk = passkeys
            .iter()
            .find(|p| {
                p.cred_id_bytes()
                    .map(|b| b == raw_id)
                    .unwrap_or(false)
            })
            .ok_or(RpError::UnknownCredential)?;

        // 2. clientDataJSON.
        let client_data_bytes = base64url::decode(&assertion.response.client_data_json)
            .map_err(|e| RpError::Decode(format!("clientDataJSON base64: {e}")))?;
        client_data::verify(
            &client_data_bytes,
            "webauthn.get",
            self.rp_origin,
            &state.challenge,
        )?;

        // 3. authenticatorData.
        let auth_data_bytes = base64url::decode(&assertion.response.authenticator_data)
            .map_err(|e| RpError::Decode(format!("authenticatorData base64: {e}")))?;
        let ad = auth_data::AuthenticatorData::parse(&auth_data_bytes)?;
        ad.expect_rp_id(self.rp_id)?;
        if !ad.flags.user_present() {
            return Err(RpError::UserPresenceMissing);
        }
        // Counter check: if the stored or presented counter is non-zero,
        // require strict monotonic progress. Authenticators that always
        // emit 0 are explicitly allowed by spec; we treat them as opt-out
        // of clone detection.
        if (pk.sign_count != 0 || ad.sign_count != 0)
            && ad.sign_count <= pk.sign_count
        {
            return Err(RpError::CounterRegression {
                stored: pk.sign_count,
                presented: ad.sign_count,
            });
        }

        // 4. Verify signature over (authenticatorData ‖ SHA-256(clientDataJSON)).
        let signature = base64url::decode(&assertion.response.signature)
            .map_err(|e| RpError::Decode(format!("signature base64: {e}")))?;
        let cose_bytes = pk.cose_pub_key_bytes()?;
        let key = cose::parse_public_key(&cose_bytes)?;
        verify::verify_assertion(&key, &auth_data_bytes, &client_data_bytes, &signature)?;

        Ok(AuthResult {
            cred_id: raw_id,
            new_sign_count: ad.sign_count,
        })
    }
}
