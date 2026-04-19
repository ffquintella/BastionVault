//! FIDO2 authentication paths (begin/complete ceremony) with token issuance.

use std::{collections::HashMap, sync::Arc};

use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

use super::{Fido2Backend, Fido2BackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response},
    modules::identity::{GroupKind, IdentityModule},
    new_fields, new_fields_internal, new_path, new_path_internal, bv_error_string,
    storage::StorageEntry,
    utils::policy::equivalent_policies,
};

impl Fido2Backend {
    pub fn login_begin_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"login/begin",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to authenticate."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.login_begin}
            ],
            help: r#"Begin a FIDO2 authentication challenge."#
        });

        path
    }

    pub fn login_complete_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"login/complete",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to authenticate."
                },
                "credential": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "JSON-encoded PublicKeyCredential assertion from the browser."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.login_complete}
            ],
            help: r#"Complete FIDO2 authentication and receive a vault token."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl Fido2BackendInner {
    /// Return `direct` unioned with any policies attached through identity
    /// user-groups that list `member` as a member. On any lookup failure
    /// (module absent, store unavailable, I/O error) falls back to `direct`
    /// so login is never blocked by an optional subsystem.
    ///
    /// FIDO2 and UserPass share the same username namespace, so we expand
    /// against `GroupKind::User` — the same group membership applies to both
    /// password and passkey logins for a given user.
    pub(crate) async fn expand_identity_group_policies(
        &self,
        member: &str,
        direct: &[String],
    ) -> Vec<String> {
        let Some(module) = self.core.module_manager.get_module::<IdentityModule>("identity") else {
            return direct.to_vec();
        };
        let Some(store) = module.group_store() else {
            return direct.to_vec();
        };
        match store.expand_policies(GroupKind::User, member, direct).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "identity group policy expansion failed for fido2 user '{member}': {e}. \
                     falling back to direct policies only."
                );
                direct.to_vec()
            }
        }
    }

    pub async fn login_begin(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        let user_entry = self.get_user_credentials(req, &username).await?
            .ok_or(RvError::ErrFido2CredentialNotFound)?;

        let passkeys = user_entry.get_passkeys()
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        if passkeys.is_empty() {
            return Err(RvError::ErrFido2CredentialNotFound);
        }

        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| RvError::ErrFido2AuthFailed(format!("invalid rp_origin: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        let (challenge, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        // Store authentication state.
        let state_json = serde_json::to_string(&auth_state)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;
        let state_entry = StorageEntry::new(
            &format!("challenge/auth/{username}"),
            &state_json,
        )?;
        req.storage_put(&state_entry).await?;

        let challenge_json = serde_json::to_value(&challenge)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;
        Ok(Some(Response::data_response(challenge_json.as_object().cloned())))
    }

    pub async fn login_complete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();
        let credential_json = req.get_data("credential")?.as_str().unwrap().to_string();

        // Load authentication state.
        let state_entry = req.storage_get(&format!("challenge/auth/{username}")).await?
            .ok_or(RvError::ErrFido2ChallengeExpired)?;
        let state_str: String = serde_json::from_slice(&state_entry.value)?;
        let auth_state: PasskeyAuthentication = serde_json::from_str(&state_str)
            .map_err(|e| RvError::ErrFido2AuthFailed(format!("invalid state: {e}")))?;

        // Delete the challenge state (single use).
        req.storage_delete(&format!("challenge/auth/{username}")).await?;

        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| RvError::ErrFido2AuthFailed(format!("invalid rp_origin: {e}")))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        let auth_response: PublicKeyCredential = serde_json::from_str(&credential_json)
            .map_err(|e| RvError::ErrFido2AuthFailed(format!("invalid credential: {e}")))?;

        let auth_result = webauthn
            .finish_passkey_authentication(&auth_response, &auth_state)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        // Update the credential's sign count to detect cloning.
        let mut user_entry = self.get_user_credentials(req, &username).await?
            .ok_or(RvError::ErrFido2CredentialNotFound)?;

        let mut passkeys = user_entry.get_passkeys()
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;
        for pk in passkeys.iter_mut() {
            pk.update_credential(&auth_result);
        }
        user_entry.set_passkeys(&passkeys)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;
        self.set_user_credentials(req, &username, &user_entry).await?;

        // Union FIDO2 user's direct policies with any policies attached
        // through identity user-groups. FIDO2 shares the UserPass username
        // namespace, so the same group membership applies.
        let effective_policies = self
            .expand_identity_group_policies(&username, &user_entry.policies)
            .await;

        // Build Auth response to issue a vault token.
        let mut auth = Auth {
            lease: Lease {
                ttl: user_entry.ttl,
                max_ttl: user_entry.max_ttl,
                renewable: user_entry.ttl.as_secs() > 0,
                ..Default::default()
            },
            display_name: format!("fido2-{username}"),
            policies: effective_policies.clone(),
            ..Default::default()
        };
        auth.metadata.insert("username".to_string(), username.to_string());

        // Ensure token_policies mirrors effective policies before
        // populate_token_auth (which overwrites auth.policies with
        // token_policies).
        if user_entry.token_policies.is_empty() && !effective_policies.is_empty() {
            user_entry.token_policies = effective_policies.clone();
        } else if !effective_policies.is_empty() {
            for p in &effective_policies {
                if !user_entry.token_policies.iter().any(|x| x == p) {
                    user_entry.token_policies.push(p.clone());
                }
            }
        }
        user_entry.populate_token_auth(&mut auth);

        // Safety net: if populate_token_auth cleared policies, restore them.
        if auth.policies.is_empty() && !effective_policies.is_empty() {
            auth.policies = effective_policies;
        }

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }

    pub async fn login_renew(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        if req.auth.is_none() {
            return Err(bv_error_string!("invalid request"));
        }
        let mut auth = req.auth.clone().unwrap();
        let username = auth.metadata.get("username")
            .ok_or_else(|| bv_error_string!("missing username in metadata"))?
            .clone();

        let user_entry = self.get_user_credentials(req, &username).await?;
        if user_entry.is_none() {
            return Ok(None);
        }
        let user_entry = user_entry.unwrap();

        // Compare against the union of direct and group-derived policies,
        // since the login path grants this union.
        let effective = self
            .expand_identity_group_policies(&username, &user_entry.policies)
            .await;
        if !equivalent_policies(&effective, &auth.policies) {
            return Err(bv_error_string!("policies have changed, not renewing"));
        }

        auth.period = user_entry.token_period;
        auth.ttl = user_entry.token_ttl;
        auth.max_ttl = user_entry.token_max_ttl;

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }
}
