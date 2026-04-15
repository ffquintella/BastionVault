//! FIDO2 registration paths (begin/complete ceremony).

use std::{collections::HashMap, sync::Arc};

use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use super::{Fido2Backend, Fido2BackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

use super::types::UserCredentialEntry;

impl Fido2Backend {
    pub fn register_begin_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"register/begin",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to register the credential for."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.register_begin}
            ],
            help: r#"Begin a FIDO2 registration ceremony. Returns a challenge for the browser."#
        });

        path
    }

    pub fn register_complete_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"register/complete",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to complete registration for."
                },
                "credential": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "JSON-encoded RegisterPublicKeyCredential from the browser."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.register_complete}
            ],
            help: r#"Complete a FIDO2 registration ceremony with the browser's response."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl Fido2BackendInner {
    pub async fn register_begin(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(format!("invalid rp_origin: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        // Load existing credentials to exclude them from registration.
        let existing_keys = self.get_user_credentials(req, &username).await?
            .map(|entry| entry.get_passkeys().unwrap_or_default())
            .unwrap_or_default();

        let exclude_credentials: Vec<CredentialID> = existing_keys
            .iter()
            .map(|pk| pk.cred_id().clone())
            .collect();

        let user_unique_id = Uuid::new_v4();
        let (challenge, reg_state) = webauthn
            .start_passkey_registration(user_unique_id, &username, &username, Some(exclude_credentials))
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        // Store registration state for the complete step.
        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;
        let state_entry = StorageEntry::new(
            &format!("challenge/reg/{username}"),
            &state_json,
        )?;
        req.storage_put(&state_entry).await?;

        // Return challenge as JSON.
        let challenge_json = serde_json::to_value(&challenge)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;
        Ok(Some(Response::data_response(challenge_json.as_object().cloned())))
    }

    pub async fn register_complete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();
        let credential_json = req.get_data("credential")?.as_str().unwrap().to_string();

        // Load registration state.
        let state_entry = req.storage_get(&format!("challenge/reg/{username}")).await?
            .ok_or(RvError::ErrFido2ChallengeExpired)?;
        let state_str: String = serde_json::from_slice(&state_entry.value)?;
        let reg_state: PasskeyRegistration = serde_json::from_str(&state_str)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(format!("invalid state: {e}")))?;

        // Delete the challenge state (single use).
        req.storage_delete(&format!("challenge/reg/{username}")).await?;

        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(format!("invalid rp_origin: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        // Parse the browser's registration response.
        let reg_response: RegisterPublicKeyCredential = serde_json::from_str(&credential_json)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(format!("invalid credential: {e}")))?;

        let passkey = webauthn
            .finish_passkey_registration(&reg_response, &reg_state)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        // Store the credential alongside existing ones.
        let mut user_entry = self.get_user_credentials(req, &username).await?
            .unwrap_or_else(|| UserCredentialEntry {
                username: username.clone(),
                ..Default::default()
            });

        let mut passkeys = user_entry.get_passkeys().unwrap_or_default();
        passkeys.push(passkey);
        user_entry.set_passkeys(&passkeys)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        self.set_user_credentials(req, &username, &user_entry).await?;

        Ok(None)
    }
}
