//! Verify-only second-factor re-validation ("step-up") for userpass.
//!
//! `auth/userpass/v2/step-up/{begin,verify}` re-prove a factor the caller
//! has already enrolled, **without minting a token or a lease**. The
//! connect-time MFA gate
//! ([`crate::modules::resource::connect_mfa`]) drives these two paths and
//! turns a successful verification into a short-lived, single-use connect
//! ticket.
//!
//! ## Why these are not the login paths
//!
//! `fido2/login/complete` performs exactly the right assertion ceremony but
//! issues a vault token as a side effect. A step-up must not manufacture
//! credentials — it answers one question ("is the human still there, and do
//! they still hold the factor?") and nothing else.
//!
//! ## Identity is never taken from the request body
//!
//! Both handlers resolve the principal from the caller's own authenticated
//! token (`req.auth.metadata["username"]`) and ignore any username in the
//! payload. That removes the obvious oracle: a token holder cannot probe
//! which factors *another* principal has enrolled, and cannot mount an
//! online guessing attack against another principal's TOTP key.
//!
//! Both paths are authenticated (deliberately absent from the backend's
//! `unauth_paths`), so an unauthenticated caller never reaches them.

use std::{collections::HashMap, sync::Arc};

use super::{UserPassBackend, UserPassBackendInner};
use crate::modules::credential::fido2::rp::{
    AuthenticationState, PublicKeyCredentialAssertion, RelyingParty,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

/// Storage prefix for in-flight step-up challenges. Deliberately distinct
/// from `challenge/auth/` (the login ceremony) so a challenge minted for a
/// step-up can never be redeemed as a login, or vice versa.
const STEP_UP_CHALLENGE_PREFIX: &str = "challenge/stepup/";

/// The factor names this backend can verify, in the order the GUI should
/// prefer them. FIDO2 first: it is phishing-resistant and needs no typing.
pub const METHOD_FIDO2: &str = "fido2";
pub const METHOD_TOTP: &str = "totp";

impl UserPassBackend {
    pub fn step_up_begin_path(&self) -> Path {
        let ref1 = self.inner.clone();

        new_path!({
            pattern: r"v2/step-up/begin$",
            operations: [
                {op: Operation::Write, handler: ref1.step_up_begin}
            ],
            help: r#"Report which second factors the calling principal has enrolled, and
issue a FIDO2 assertion challenge when a security key is available. Takes no
parameters — the principal is the caller's own token identity."#
        })
    }

    pub fn step_up_verify_path(&self) -> Path {
        let ref1 = self.inner.clone();

        new_path!({
            pattern: r"v2/step-up/verify$",
            fields: {
                "method": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Factor to verify: `totp` or `fido2`."
                },
                "totp_code": {
                    field_type: FieldType::SecretStr,
                    required: false,
                    description: "Current TOTP code. Required when method = totp."
                },
                "credential": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "JSON-encoded PublicKeyCredentialAssertion. Required when method = fido2."
                }
            },
            operations: [
                {op: Operation::Write, handler: ref1.step_up_verify}
            ],
            help: r#"Verify one second factor for the calling principal. Returns
{"verified": true, "method": "..."} on success and an error otherwise. Mints no
token and creates no lease."#
        })
    }
}

/// Which factors a principal can actually be challenged on right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailableFactors {
    pub totp: bool,
    pub fido2: bool,
}

impl AvailableFactors {
    pub fn any(&self) -> bool {
        self.totp || self.fido2
    }

    /// Method names in the order the client should offer them.
    pub fn names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.fido2 {
            out.push(METHOD_FIDO2.to_string());
        }
        if self.totp {
            out.push(METHOD_TOTP.to_string());
        }
        out
    }
}

/// The calling principal's userpass username, lowercased.
///
/// Only a token minted by a userpass mount carries the `username` +
/// `mount_path` metadata pair. Anything else (AppRole, cert, OIDC, a raw
/// root token) has no second factor on file here and is rejected outright
/// rather than being silently treated as factor-less-but-fine.
pub fn caller_username(req: &Request) -> Result<String, RvError> {
    let auth = req
        .auth
        .as_ref()
        .ok_or_else(|| RvError::ErrResponse("step-up requires an authenticated caller".into()))?;

    let mount = auth.metadata.get("mount_path").map(|s| s.as_str()).unwrap_or_default();
    let username = auth.metadata.get("username").map(|s| s.as_str()).unwrap_or_default();

    if username.is_empty() || !mount.starts_with("userpass") {
        return Err(RvError::ErrResponse(
            "step-up is only available to userpass principals; this token has no \
             TOTP or security-key factor on file"
                .into(),
        ));
    }
    Ok(username.to_lowercase())
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    /// Which factors the calling principal has enrolled. Reads the user
    /// record and the FIDO2 relying-party config; a factor counts as
    /// available only when everything needed to verify it is present, so a
    /// half-configured FIDO2 deployment reports `fido2: false` rather than
    /// failing at verify time.
    pub async fn step_up_factors(&self, req: &mut Request) -> Result<AvailableFactors, RvError> {
        let username = caller_username(req)?;
        let user = self
            .get_user(req, &username)
            .await?
            .ok_or_else(|| RvError::ErrResponse("no such principal".into()))?;

        if user.disabled {
            return Err(RvError::ErrResponse("this principal is disabled".into()));
        }

        let totp = !user.totp_key.trim().is_empty();
        let fido2 = {
            let has_passkeys = user.get_passkeys().map(|p| !p.is_empty()).unwrap_or(false);
            has_passkeys && self.get_fido2_config(req).await?.is_some()
        };

        Ok(AvailableFactors { totp, fido2 })
    }

    /// `POST auth/userpass/v2/step-up/begin`.
    ///
    /// Reports the caller's available factors and, when a security key is
    /// enrolled, mints a FIDO2 assertion challenge stored under
    /// `challenge/stepup/<username>`. A second `begin` overwrites the first,
    /// so an abandoned prompt cannot be redeemed later.
    pub async fn step_up_begin(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = caller_username(req)?;
        let factors = self.step_up_factors(req).await?;

        let mut data = serde_json::Map::new();
        data.insert("username".into(), serde_json::Value::String(username.clone()));
        data.insert(
            "methods".into(),
            serde_json::Value::Array(
                factors.names().into_iter().map(serde_json::Value::String).collect(),
            ),
        );

        if factors.fido2 {
            let config = self.get_fido2_config(req).await?.ok_or(RvError::ErrFido2NotConfigured)?;
            let user = self
                .get_user(req, &username)
                .await?
                .ok_or_else(|| RvError::ErrResponse("no such principal".into()))?;
            let passkeys = user
                .get_passkeys()
                .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;

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
            req.storage_put(&StorageEntry::new(
                &format!("{STEP_UP_CHALLENGE_PREFIX}{username}"),
                &state_json,
            )?)
            .await?;

            let challenge_json = serde_json::to_value(&challenge)
                .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
            data.insert("fido2".into(), challenge_json);
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    /// `POST auth/userpass/v2/step-up/verify`.
    ///
    /// Verifies exactly one factor for the calling principal. Returns
    /// `{verified: true, method}` or an error — never a `{verified: false}`
    /// body, so a caller cannot mistake a failed factor for a successful
    /// call with a falsy field.
    pub async fn step_up_verify(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let username = caller_username(req)?;
        let method = req.get_data("method")?.as_str().unwrap_or_default().trim().to_lowercase();

        match method.as_str() {
            METHOD_TOTP => self.step_up_verify_totp(req, &username).await?,
            METHOD_FIDO2 => self.step_up_verify_fido2(req, &username).await?,
            other => {
                return Err(RvError::ErrResponse(format!(
                    "unknown step-up method `{other}`; expected `totp` or `fido2`"
                )));
            }
        }

        let mut data = serde_json::Map::new();
        data.insert("verified".into(), serde_json::Value::Bool(true));
        data.insert("method".into(), serde_json::Value::String(method));
        data.insert("username".into(), serde_json::Value::String(username));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// TOTP half of the step-up. Uses the same shared verifier as the login
    /// second factor, so the skew window and the constant-time comparison
    /// cannot drift between the two.
    ///
    /// Note this does *not* consult the global `TotpMfaConfig.enabled`
    /// switch: that flag governs whether TOTP is demanded *at login*. A
    /// principal with a bound key can always re-prove it, which is what lets
    /// an operator gate a single high-value profile without turning on
    /// mandatory TOTP for every login in the deployment.
    async fn step_up_verify_totp(&self, req: &mut Request, username: &str) -> Result<(), RvError> {
        use crate::modules::totp::mfa;

        let code = req.get_data("totp_code").ok().and_then(|v| v.as_str().map(|s| s.to_string()));
        let code = code.unwrap_or_default();
        if code.trim().is_empty() {
            return Err(RvError::ErrResponse("totp_code is required for method `totp`".into()));
        }

        let user = self
            .get_user(req, username)
            .await?
            .ok_or_else(|| RvError::ErrResponse("no such principal".into()))?;
        if user.disabled {
            return Err(RvError::ErrResponse("this principal is disabled".into()));
        }
        if user.totp_key.trim().is_empty() {
            return Err(RvError::ErrResponse(
                "no TOTP key is bound to this principal; enrol one before requiring \
                 TOTP re-validation"
                    .into(),
            ));
        }

        let mount = match mfa::normalize_mount(&user.totp_mount) {
            m if m.is_empty() => {
                let cfg = self.get_mfa_config(req).await?;
                mfa::normalize_mount(&cfg.default_mount)
            }
            m => m,
        };

        let now = super::path_users::now_secs().max(0) as u64;
        if !mfa::verify_code(&self.core, &mount, &user.totp_key, &code, now).await? {
            return Err(RvError::ErrResponse("invalid TOTP code".into()));
        }
        Ok(())
    }

    /// FIDO2 half of the step-up. Runs the assertion against the challenge
    /// minted by `begin`, deletes that challenge before verifying (so a
    /// replay races against itself rather than succeeding twice), and writes
    /// the authenticator's new signature counter back to the user record so
    /// clone detection keeps working across login and step-up alike.
    async fn step_up_verify_fido2(&self, req: &mut Request, username: &str) -> Result<(), RvError> {
        let credential_json = req
            .get_data("credential")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if credential_json.trim().is_empty() {
            return Err(RvError::ErrResponse("credential is required for method `fido2`".into()));
        }

        let config = self.get_fido2_config(req).await?.ok_or(RvError::ErrFido2NotConfigured)?;

        let key = format!("{STEP_UP_CHALLENGE_PREFIX}{username}");
        let state_entry = req.storage_get(&key).await?.ok_or(RvError::ErrFido2ChallengeExpired)?;
        // Single-use: drop the challenge before it is evaluated.
        req.storage_delete(&key).await?;

        let state_str: String = serde_json::from_slice(&state_entry.value)?;
        let auth_state: AuthenticationState = serde_json::from_str(&state_str)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(format!("invalid state: {e}")))?;

        let mut user = self
            .get_user(req, username)
            .await?
            .ok_or_else(|| RvError::ErrResponse("no such principal".into()))?;
        if user.disabled {
            return Err(RvError::ErrResponse("this principal is disabled".into()));
        }

        let mut passkeys = user
            .get_passkeys()
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
        if passkeys.is_empty() {
            return Err(RvError::ErrFido2CredentialNotFound);
        }

        let assertion: PublicKeyCredentialAssertion = serde_json::from_str(&credential_json)
            .map_err(|e: serde_json::Error| {
                RvError::ErrFido2AuthFailed(format!("invalid credential: {e}"))
            })?;

        let rp = RelyingParty {
            rp_id: &config.rp_id,
            rp_origin: &config.rp_origin,
            rp_name: &config.rp_name,
        };
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
        user.set_passkeys(&passkeys)
            .map_err(|e: serde_json::Error| RvError::ErrFido2AuthFailed(e.to_string()))?;
        self.set_user(req, username, &user).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_names_prefer_fido2() {
        let both = AvailableFactors { totp: true, fido2: true };
        assert_eq!(both.names(), vec!["fido2".to_string(), "totp".to_string()]);
        assert!(both.any());

        let totp_only = AvailableFactors { totp: true, fido2: false };
        assert_eq!(totp_only.names(), vec!["totp".to_string()]);

        let none = AvailableFactors::default();
        assert!(none.names().is_empty());
        assert!(!none.any());
    }

    #[test]
    fn caller_username_requires_a_userpass_token() {
        use crate::logical::Auth;

        // No auth at all.
        let mut req = Request::new("auth/userpass/v2/step-up/begin");
        assert!(caller_username(&req).is_err());

        // A token from some other backend: no username/mount metadata.
        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "approle/".into());
        auth.metadata.insert("role_name".into(), "ci".into());
        req.auth = Some(auth);
        assert!(caller_username(&req).is_err());

        // A userpass token resolves, lowercased.
        let mut auth = Auth::default();
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert("username".into(), "Alice".into());
        req.auth = Some(auth);
        assert_eq!(caller_username(&req).unwrap(), "alice");
    }
}
