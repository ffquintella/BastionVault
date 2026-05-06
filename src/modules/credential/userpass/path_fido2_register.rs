//! FIDO2 registration paths within the userpass backend.

use std::{collections::HashMap, sync::Arc};

use uuid::Uuid;

use super::{UserPassBackend, UserPassBackendInner};
use crate::modules::credential::fido2::rp::{
    PublicKeyCredentialAttestation, RegistrationState, RelyingParty,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

impl UserPassBackend {
    pub fn fido2_register_begin_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"fido2/register/begin",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to register the FIDO2 key for. Must be an existing userpass user."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.fido2_register_begin}
            ],
            help: r#"Begin a FIDO2 registration ceremony for a userpass user."#
        });

        path
    }

    pub fn fido2_register_complete_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"fido2/register/complete",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to complete registration for."
                },
                "credential": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "JSON-encoded PublicKeyCredentialAttestation from the browser."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.fido2_register_complete}
            ],
            help: r#"Complete a FIDO2 registration ceremony."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    pub async fn fido2_register_begin(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_fido2_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        // User must already exist in userpass.
        let user_entry = self.get_user(req, &username).await?
            .ok_or_else(|| RvError::ErrResponse("User not found. Create a userpass user first.".into()))?;

        let rp = RelyingParty {
            rp_id: &config.rp_id,
            rp_origin: &config.rp_origin,
            rp_name: &config.rp_name,
        };

        let exclude_credentials: Vec<Vec<u8>> = user_entry
            .get_passkeys()
            .unwrap_or_default()
            .iter()
            .filter_map(|pk| pk.cred_id_bytes().ok())
            .collect();

        let user_unique_id = *Uuid::new_v4().as_bytes();
        let (challenge, reg_state) = rp
            .begin_registration(&username, &username, user_unique_id, &exclude_credentials)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e: serde_json::Error| RvError::ErrFido2RegistrationFailed(e.to_string()))?;
        let state_entry = StorageEntry::new(
            &format!("challenge/reg/{username}"),
            &state_json,
        )?;
        req.storage_put(&state_entry).await?;

        let challenge_json = serde_json::to_value(&challenge)
            .map_err(|e: serde_json::Error| RvError::ErrFido2RegistrationFailed(e.to_string()))?;
        Ok(Some(Response::data_response(challenge_json.as_object().cloned())))
    }

    pub async fn fido2_register_complete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_fido2_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();
        let credential_json = req.get_data("credential")?.as_str().unwrap().to_string();

        let state_entry = req.storage_get(&format!("challenge/reg/{username}")).await?
            .ok_or(RvError::ErrFido2ChallengeExpired)?;
        let state_str: String = serde_json::from_slice(&state_entry.value)?;
        let reg_state: RegistrationState = serde_json::from_str(&state_str)
            .map_err(|e: serde_json::Error| RvError::ErrFido2RegistrationFailed(format!("invalid state: {e}")))?;

        // Single-use challenge.
        req.storage_delete(&format!("challenge/reg/{username}")).await?;

        let rp = RelyingParty {
            rp_id: &config.rp_id,
            rp_origin: &config.rp_origin,
            rp_name: &config.rp_name,
        };

        let attestation: PublicKeyCredentialAttestation = serde_json::from_str(&credential_json)
            .map_err(|e: serde_json::Error| RvError::ErrFido2RegistrationFailed(format!("invalid credential: {e}")))?;

        let passkey = rp
            .finish_registration(&attestation, &reg_state)
            .map_err(|e| RvError::ErrFido2RegistrationFailed(e.to_string()))?;

        let mut user_entry = self.get_user(req, &username).await?
            .ok_or_else(|| RvError::ErrResponse("User not found".into()))?;

        let mut passkeys = user_entry.get_passkeys().unwrap_or_default();
        passkeys.push(passkey);
        user_entry.set_passkeys(&passkeys)
            .map_err(|e: serde_json::Error| RvError::ErrFido2RegistrationFailed(e.to_string()))?;
        user_entry.fido2_enabled = true;

        self.set_user(req, &username, &user_entry).await?;

        Ok(None)
    }
}
