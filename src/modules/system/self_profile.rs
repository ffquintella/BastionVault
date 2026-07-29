//! Self-service profile for the *calling* principal.
//!
//! Everything an operator may change about their own account without an
//! administrator: their password (when the login was password-based), their
//! contact details, and their per-OS default resource accounts (including the
//! optional stored Windows RDP password).
//!
//! ## Why these live on `sys/` rather than on the userpass mount
//!
//! The ACL is exact-path, and a userpass mount can be enabled at any path
//! (`auth/userpass/`, `auth/pass/`, …). A rule in a built-in policy therefore
//! cannot name the mount-relative route without guessing the mount name. The
//! `sys/identity/profile/self*` paths are stable regardless of where the
//! credential backend is mounted, so `DEFAULT_POLICY` (which every login token
//! carries — `sanitize_policies` always appends `default`) and the implicit
//! `namespace-self` policy can grant them once. This mirrors the existing
//! `sys/identity/default-account/self` precedent.
//!
//! ## How the caller's principal is resolved
//!
//! The token entry records the path the login came in on
//! (`TokenEntry::path` = `auth/<mount>/login/<user>`), so the **real** auth
//! mount is recovered with `Router::matching_mount` rather than inferred from
//! the `mount_path` metadata (which every userpass mount stamps as the literal
//! `userpass/`). That makes the userpass record we read and write unambiguous
//! even with several userpass mounts enabled. A token that was not minted by a
//! `userpass` mount (root tokens, `auth/token/create` children, AppRole, OIDC,
//! …) has no password to change: the profile read reports
//! `can_change_password = false` and the write endpoints refuse explicitly
//! instead of silently touching someone else's record.
//!
//! Default resource accounts are keyed on the identity-layer `(mount, name)`
//! pair, so those reuse the same candidate resolution as
//! [`SystemBackend::handle_default_account_self`] — see
//! [`SystemBackend::self_default_account_candidates`].
//!
//! ## Security notes
//!
//! - A self password change requires the **current** password. That is the
//!   usual re-authentication expectation, and it also means a token alone is
//!   not enough to lock its owner out of their own account.
//! - A wrong `current_password` does **not** feed the userpass lockout counter.
//!   Doing so would let anyone holding a live token deny the real operator
//!   their account, and the caller is already authenticated — the attempt is
//!   recorded on the user-audit trail instead, and the IP-level DoS guard still
//!   applies.
//! - Changing the password does not revoke sessions issued before the change
//!   (there is no per-principal lease index to revoke by). Operators who need
//!   that must revoke the tokens explicitly.

use serde_json::{json, Map, Value};

use super::SystemBackend;
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Backend, Request, Response},
    modules::{
        auth::AuthModule,
        credential::userpass::path_users::{is_plausible_email, UserEntry},
        identity::{IdentityModule, UserAuditEntry},
    },
    storage::{Storage, StorageEntry},
};

/// Floor on a self-chosen password. Deliberately modest: the desktop GUI
/// additionally enforces the operator-configured password policy before it
/// ever calls this, and the value here only exists so a self-service change
/// can never *weaken* an account to something trivially guessable.
const MIN_SELF_PASSWORD_LEN: usize = 8;

/// The caller's userpass principal: the real auth mount that issued the token,
/// the username on it, and the stored record.
struct SelfUserpassPrincipal {
    /// Router mount prefix, e.g. `auth/pass/`.
    mount: String,
    /// Lower-cased username as stored under `user/<name>`.
    username: String,
    entry: UserEntry,
}

#[maybe_async::maybe_async]
impl SystemBackend {
    /// Resolve the calling token's userpass principal, or `None` when the
    /// token was not minted by a `userpass` mount.
    ///
    /// Deliberately strict: rather than searching every userpass mount for a
    /// matching username, this follows the login path recorded on the token
    /// entry. Two mounts can hold different accounts that happen to share a
    /// username; picking the wrong one would let one of them rewrite the
    /// other's record.
    async fn resolve_self_userpass(
        &self,
        req: &Request,
    ) -> Result<Option<SelfUserpassPrincipal>, RvError> {
        let auth_module = self.get_module::<AuthModule>("auth")?;
        let Some(token_store) = auth_module.token_store.load_full() else {
            return Err(RvError::ErrPermissionDenied);
        };
        // `RouterEntry::salt_id` is the identity function, so `req.client_token`
        // inside a backend handler is still the raw token id.
        let Some(te) = token_store.lookup(&req.client_token).await? else {
            return Err(RvError::ErrPermissionDenied);
        };

        let mount = self.core.router.matching_mount(&te.path)?;
        if mount.is_empty() {
            return Ok(None);
        }
        // Only a `userpass` mount owns a password we can change.
        let Some(entry) = self.core.router.matching_mount_entry(&mount)? else {
            return Ok(None);
        };
        {
            let me = entry.read().map_err(|_| RvError::ErrRequestInvalid)?;
            if me.logical_type != "userpass" {
                return Ok(None);
            }
        }

        let username = te
            .meta
            .get("username")
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        if username.is_empty() {
            return Ok(None);
        }

        let Some(view) = self.core.router.matching_view(&mount)? else {
            return Ok(None);
        };
        let Some(raw) = view.get(&format!("user/{username}")).await? else {
            // The account was deleted out from under a live token.
            return Ok(None);
        };
        let user_entry: UserEntry = serde_json::from_slice(&raw.value)?;

        Ok(Some(SelfUserpassPrincipal { mount, username, entry: user_entry }))
    }

    /// Persist a modified userpass record back to its own mount.
    ///
    /// Writes the whole `UserEntry` after a read-modify-write, exactly like the
    /// userpass backend's own `set_user`, so no unrelated field is disturbed.
    async fn store_self_userpass(
        &self,
        principal: &SelfUserpassPrincipal,
    ) -> Result<(), RvError> {
        let Some(view) = self.core.router.matching_view(&principal.mount)? else {
            return Err(bv_error_response_status!(
                500,
                "the auth mount that issued this token is no longer available"
            ));
        };
        let entry = StorageEntry::new(
            format!("user/{}", principal.username).as_str(),
            &principal.entry,
        )?;
        view.put(&entry).await
    }

    /// Best-effort user-audit append for a self-service change. Reuses the op
    /// vocabulary the Admin → Audit page already renders (`password-change`,
    /// `update`); `details` marks the entry as self-service so an auditor can
    /// tell it apart from an admin-driven change.
    async fn record_self_audit(&self, req: &Request, op: &str, mount: &str, target: &str, details: &str) {
        let Ok(module) = self.get_module::<IdentityModule>("identity") else {
            return;
        };
        let Some(store) = module.user_audit_store() else {
            return;
        };
        let entry = UserAuditEntry {
            ts: String::new(),
            actor_entity_id: crate::modules::identity::caller_audit_actor(req),
            op: op.to_string(),
            mount: mount.to_string(),
            target: target.to_string(),
            details: details.to_string(),
        };
        let _ = store.append(entry).await;
    }

    /// Read the calling operator's own profile: identity, what they are allowed
    /// to change, their contact details, and their default resource accounts.
    ///
    /// Never 404s — a caller with no userpass record (a root token, an AppRole
    /// login) still gets a well-formed document with `can_change_password` /
    /// `can_edit_contact` false, so the GUI can render a read-only page instead
    /// of an error.
    pub async fn handle_self_profile_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let auth = req
            .auth
            .as_ref()
            .ok_or_else(|| bv_error_response_status!(401, "no authenticated caller"))?;

        let mut data = Map::new();
        data.insert(
            "entity_id".into(),
            Value::String(auth.metadata.get("entity_id").cloned().unwrap_or_default()),
        );
        data.insert("display_name".into(), Value::String(auth.display_name.clone()));
        data.insert(
            "policies".into(),
            Value::Array(auth.policies.iter().cloned().map(Value::String).collect()),
        );

        let principal = self.resolve_self_userpass(req).await?;
        match &principal {
            Some(p) => {
                // FIDO2-only accounts have no password to rotate; a disabled
                // account should not be self-serviceable at all.
                let can_change_password = !p.entry.fido2_enabled && !p.entry.disabled;
                data.insert("username".into(), Value::String(p.username.clone()));
                data.insert("auth_mount".into(), Value::String(p.mount.clone()));
                data.insert("auth_method".into(), Value::String("userpass".into()));
                data.insert("email".into(), Value::String(p.entry.email.clone()));
                data.insert("phone".into(), Value::String(p.entry.phone.clone()));
                data.insert("disabled".into(), Value::Bool(p.entry.disabled));
                data.insert("fido2_enabled".into(), Value::Bool(p.entry.fido2_enabled));
                data.insert(
                    "totp_mfa_enabled".into(),
                    Value::Bool(p.entry.totp_mfa_enabled),
                );
                data.insert("can_change_password".into(), Value::Bool(can_change_password));
                data.insert("can_edit_contact".into(), Value::Bool(!p.entry.disabled));
            }
            None => {
                // Fall back to whatever the token knows about itself so the page
                // can still name the operator.
                data.insert(
                    "username".into(),
                    Value::String(
                        auth.metadata
                            .get("username")
                            .or_else(|| auth.metadata.get("role_name"))
                            .cloned()
                            .unwrap_or_default(),
                    ),
                );
                data.insert("auth_mount".into(), Value::String(String::new()));
                data.insert(
                    "auth_method".into(),
                    Value::String(
                        auth.metadata.get("mount_path").cloned().unwrap_or_default(),
                    ),
                );
                data.insert("email".into(), Value::String(String::new()));
                data.insert("phone".into(), Value::String(String::new()));
                data.insert("disabled".into(), Value::Bool(false));
                data.insert("fido2_enabled".into(), Value::Bool(false));
                data.insert("totp_mfa_enabled".into(), Value::Bool(false));
                data.insert("can_change_password".into(), Value::Bool(false));
                data.insert("can_edit_contact".into(), Value::Bool(false));
            }
        }

        // Default resource accounts, masked exactly like the admin read: the
        // stored Windows RDP password is reported only as a presence flag.
        let (candidates, existing) = self.self_default_account(req).await?;
        let (acct_mount, acct_name) = candidates.first().cloned().unwrap_or_default();
        let mut account = Map::new();
        match &existing {
            Some(a) => {
                account.insert("mount".into(), Value::String(a.mount.clone()));
                account.insert("name".into(), Value::String(a.name.clone()));
                account.insert("linux".into(), Value::String(a.linux.clone()));
                account.insert("macos".into(), Value::String(a.macos.clone()));
                account.insert("windows".into(), Value::String(a.windows.clone()));
                account.insert(
                    "has_windows_password".into(),
                    Value::Bool(a.has_windows_password()),
                );
                account.insert("updated_at".into(), Value::String(a.updated_at.clone()));
            }
            None => {
                account.insert("mount".into(), Value::String(acct_mount));
                account.insert("name".into(), Value::String(acct_name));
                account.insert("linux".into(), Value::String(String::new()));
                account.insert("macos".into(), Value::String(String::new()));
                account.insert("windows".into(), Value::String(String::new()));
                account.insert("has_windows_password".into(), Value::Bool(false));
                account.insert("updated_at".into(), Value::String(String::new()));
            }
        }
        // The default-account store is keyed on the identity principal, which
        // exists for AppRole / OIDC / cert logins too — so this stays editable
        // even when the password section does not.
        data.insert(
            "can_edit_default_account".into(),
            Value::Bool(!candidates.is_empty()),
        );
        data.insert("default_account".into(), Value::Object(account));

        Ok(Some(Response::data_response(Some(data))))
    }

    /// Change the calling operator's own password.
    ///
    /// Requires the current password. Refuses for accounts that are disabled or
    /// FIDO2-only, and for tokens that were not minted by a userpass mount.
    pub async fn handle_self_profile_password_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(mut principal) = self.resolve_self_userpass(req).await? else {
            return Err(bv_error_response_status!(
                400,
                "changing your own password requires a username/password login"
            ));
        };

        if principal.entry.disabled {
            return Err(bv_error_response_status!(403, "account is disabled"));
        }
        if principal.entry.fido2_enabled {
            return Err(bv_error_response_status!(
                400,
                "this account authenticates with a FIDO2 security key; it has no password to change"
            ));
        }

        let current = req
            .get_data("current_password")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        let new_password = req
            .get_data("new_password")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        if new_password.len() < MIN_SELF_PASSWORD_LEN {
            return Err(bv_error_response_status!(
                400,
                format!("new password must be at least {MIN_SELF_PASSWORD_LEN} characters")
            ));
        }
        if new_password == current {
            return Err(bv_error_response_status!(
                400,
                "new password must differ from the current one"
            ));
        }

        // Re-authenticate. A miss is recorded but deliberately does NOT feed the
        // userpass lockout counter — see the module header.
        let ok = bcrypt::verify(&current, &principal.entry.password_hash)?;
        if !ok {
            log::warn!(
                target: "security",
                "self password change refused for '{}': current password did not verify",
                principal.username
            );
            self.record_self_audit(
                req,
                "password-change",
                &principal.mount,
                &principal.username,
                "self-service; refused: current password did not verify",
            )
            .await;
            return Err(bv_error_response_status!(403, "current password is incorrect"));
        }

        principal.entry.password_hash = bcrypt::hash(&new_password, bcrypt::DEFAULT_COST)?;
        self.store_self_userpass(&principal).await?;

        self.record_self_audit(
            req,
            "password-change",
            &principal.mount,
            &principal.username,
            "self-service",
        )
        .await;

        Ok(Some(Response::data_response(
            json!({ "updated": true, "username": principal.username }).as_object().cloned(),
        )))
    }

    /// Update the calling operator's own contact details.
    ///
    /// Write-preserve: a field absent from the body keeps its stored value, so
    /// a caller that only wants to change their phone number need not resend
    /// their email. An explicit empty string clears the field.
    pub async fn handle_self_profile_contact_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let Some(mut principal) = self.resolve_self_userpass(req).await? else {
            return Err(bv_error_response_status!(
                400,
                "editing your own contact details requires a username/password login"
            ));
        };
        if principal.entry.disabled {
            return Err(bv_error_response_status!(403, "account is disabled"));
        }

        let mut changed: Vec<&str> = Vec::new();
        if let Ok(v) = req.get_data("email") {
            let email = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.trim().to_string();
            if !email.is_empty() && !is_plausible_email(&email) {
                return Err(bv_error_response_status!(400, "email is not a valid address"));
            }
            if email != principal.entry.email {
                principal.entry.email = email;
                changed.push("email");
            }
        }
        if let Ok(v) = req.get_data("phone") {
            let phone = v.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.trim().to_string();
            if phone != principal.entry.phone {
                principal.entry.phone = phone;
                changed.push("phone");
            }
        }

        if !changed.is_empty() {
            self.store_self_userpass(&principal).await?;
            self.record_self_audit(
                req,
                "update",
                &principal.mount,
                &principal.username,
                &format!("self-service contact update; changed={}", changed.join(",")),
            )
            .await;
        }

        Ok(Some(Response::data_response(
            json!({
                "username": principal.username,
                "email": principal.entry.email,
                "phone": principal.entry.phone,
            })
            .as_object()
            .cloned(),
        )))
    }
}
