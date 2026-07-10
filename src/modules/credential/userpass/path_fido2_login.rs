//! FIDO2 authentication paths within the userpass backend.

use std::{collections::HashMap, sync::Arc};

use super::{UserPassBackend, UserPassBackendInner};
use crate::modules::credential::fido2::rp::{
    AuthenticationState, PublicKeyCredentialAssertion, RelyingParty,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response},
    modules::identity::GroupKind,
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

impl UserPassBackend {
    pub fn fido2_login_begin_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"fido2/login/begin",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to authenticate."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.fido2_login_begin}
            ],
            help: r#"Begin a FIDO2 authentication challenge for a userpass user."#
        });

        path
    }

    pub fn fido2_login_complete_path(&self) -> Path {
        let ref1 = self.inner.clone();

        let path = new_path!({
            pattern: r"fido2/login/complete",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username to authenticate."
                },
                "credential": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "JSON-encoded PublicKeyCredentialAssertion from the browser."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.fido2_login_complete}
            ],
            help: r#"Complete FIDO2 authentication and receive a vault token."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    /// Public entry point for `auth/userpass/fido2/login/begin`. Runs
    /// the challenge issuance via `fido2_login_begin_inner` and records
    /// *failures* to the login-audit trail — an unknown username or a
    /// user with no enrolled passkey previously left no audit trace at
    /// all. Successful begins are deliberately not recorded: a begin is
    /// only a challenge, and the eventual `complete` call records the
    /// actual login outcome (recording both would double-count every
    /// successful security-key login). The audit write is best-effort
    /// and never blocks or alters the result.
    pub async fn fido2_login_begin(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req
            .get_data("username")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
            .unwrap_or_else(|| "(unknown)".to_string());
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        let result = self.fido2_login_begin_inner(backend, req).await;
        if let Err(e) = &result {
            crate::modules::credential::login_audit_store::record_login(
                &self.core,
                "userpass/",
                &username,
                false,
                &remote_addr,
                &format!("method=fido2 stage=begin {e}"),
            )
            .await;
        }
        result
    }

    async fn fido2_login_begin_inner(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_fido2_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();

        let user_entry = self.get_user(req, &username).await?
            .ok_or(RvError::ErrFido2CredentialNotFound)?;

        let passkeys = user_entry.get_passkeys()
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;

        if passkeys.is_empty() {
            return Err(RvError::ErrFido2CredentialNotFound);
        }

        let rp = RelyingParty {
            rp_id: &config.rp_id,
            rp_origin: &config.rp_origin,
            rp_name: &config.rp_name,
        };

        let (challenge, auth_state) = rp
            .begin_authentication(&passkeys)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        let state_json = serde_json::to_string(&auth_state)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
        let state_entry = StorageEntry::new(
            &format!("challenge/auth/{username}"),
            &state_json,
        )?;
        req.storage_put(&state_entry).await?;

        let challenge_json = serde_json::to_value(&challenge)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
        Ok(Some(Response::data_response(challenge_json.as_object().cloned())))
    }

    /// Public entry point for `auth/userpass/fido2/login/complete` — the
    /// route the GUI's security-key login actually calls. Runs the
    /// ceremony via `fido2_login_complete_inner` and records the outcome
    /// to the login-audit trail under the `userpass/` mount (this is the
    /// userpass-integrated FIDO2 path, distinct from the standalone
    /// `fido2/` backend). The audit write is best-effort and never
    /// blocks or alters the login result.
    pub async fn fido2_login_complete(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = req
            .get_data("username")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
            .unwrap_or_else(|| "(unknown)".to_string());
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        let result = self.fido2_login_complete_inner(backend, req).await;
        let (success, base) =
            crate::modules::credential::login_audit_store::login_outcome(&result);
        // Tag the method so a security-key login is distinguishable from
        // a password login on the same `userpass/` mount.
        let details = if base.is_empty() {
            "method=fido2".to_string()
        } else {
            format!("method=fido2 {base}")
        };
        crate::modules::credential::login_audit_store::record_login(
            &self.core,
            "userpass/",
            &username,
            success,
            &remote_addr,
            &details,
        )
        .await;
        result
    }

    async fn fido2_login_complete_inner(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let config = self.get_fido2_config(req).await?
            .ok_or(RvError::ErrFido2NotConfigured)?;

        let username = req.get_data("username")?.as_str().unwrap().to_lowercase();
        let credential_json = req.get_data("credential")?.as_str().unwrap().to_string();

        let state_entry = req.storage_get(&format!("challenge/auth/{username}")).await?
            .ok_or(RvError::ErrFido2ChallengeExpired)?;
        let state_str: String = serde_json::from_slice(&state_entry.value)?;
        let auth_state: AuthenticationState = serde_json::from_str(&state_str)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(format!("invalid state: {e}")))?;

        // Single-use challenge.
        req.storage_delete(&format!("challenge/auth/{username}")).await?;

        let rp = RelyingParty {
            rp_id: &config.rp_id,
            rp_origin: &config.rp_origin,
            rp_name: &config.rp_name,
        };

        let assertion: PublicKeyCredentialAssertion = serde_json::from_str(&credential_json)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(format!("invalid credential: {e}")))?;

        let mut user_entry = self.get_user(req, &username).await?
            .ok_or(RvError::ErrFido2CredentialNotFound)?;

        let mut passkeys = user_entry.get_passkeys()
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;

        let auth_result = rp
            .finish_authentication(&assertion, &auth_state, &passkeys)
            .map_err(|e| RvError::ErrFido2AuthFailed(e.to_string()))?;

        for pk in passkeys.iter_mut() {
            if let Ok(id) = pk.cred_id_bytes() {
                if id == auth_result.cred_id {
                    pk.sign_count = auth_result.new_sign_count;
                }
            }
        }
        user_entry.set_passkeys(&passkeys)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
        self.set_user(req, &username, &user_entry).await?;

        // Multi-tenancy: bind the FIDO2 session to the namespace named by the
        // request header, exactly as the password-login path does.
        let (ns_path, ns_uuid) =
            crate::modules::namespace::token_binding::resolve_login_namespace(&self.core, req).await?;

        // Multi-tenancy: refuse the login if this principal's namespace
        // assignment does not include the login namespace (no record ⇒
        // unrestricted; fails closed on a non-matching record).
        crate::modules::namespace::ns_assignment::enforce_login_assignment(
            &self.core,
            "userpass/",
            &username,
            &ns_path,
        )
        .await?;

        // Union direct policies with any attached through identity user-groups
        // (of the login namespace) so FIDO2 logins receive the same
        // group-derived policies as password logins for the same username.
        let effective_policies = self
            .expand_identity_group_policies(GroupKind::User, &username, &user_entry.policies, &ns_path)
            .await;

        if user_entry.token_policies.is_empty() && !effective_policies.is_empty() {
            user_entry.token_policies = effective_policies.clone();
        } else if !effective_policies.is_empty() {
            for p in &effective_policies {
                if !user_entry.token_policies.iter().any(|x| x == p) {
                    user_entry.token_policies.push(p.clone());
                }
            }
        }

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
        auth.metadata.insert("mount_path".to_string(), "userpass/".to_string());
        if let Some(entity_id) =
            super::path_login::resolve_entity_id(&self.core, "userpass/", &username, &ns_path).await
        {
            auth.metadata.insert("entity_id".to_string(), entity_id);
        }
        // child_visible follows the login namespace's `child_visible_default`
        // flag (see `path_login` for the rationale); default false.
        let child_visible =
            crate::modules::namespace::token_binding::login_child_visible(&self.core, &ns_path)
                .await;
        crate::modules::namespace::token_binding::stamp_binding(
            &mut auth.metadata,
            &ns_path,
            &ns_uuid,
            child_visible,
        );
        user_entry.populate_token_auth(&mut auth);

        if auth.policies.is_empty() && !effective_policies.is_empty() {
            auth.policies = effective_policies;
        }

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }

    pub async fn fido2_login_renew(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // Reuse the same renewal logic as password login since both use UserEntry.
        self.login_renew(_backend, req).await
    }
}
