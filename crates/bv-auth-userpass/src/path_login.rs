use std::{collections::HashMap, sync::Arc};

use super::{
    path_config::{LockoutConfig, TotpMfaConfig},
    path_users::UserEntry,
    UserPassBackend, UserPassBackendInner,
};
use crate::kernel_api::VaultCtx;
use crate::{
    context::Context,
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response},
    kernel_api::identity::GroupKind,
    new_fields, new_fields_internal, new_path, new_path_internal, bv_error_string,
    utils::policy::equivalent_policies,
};

/// Best-effort resolve-or-create of the entity_id for a principal. The
/// identity module may not be loaded (embedded / minimal builds) or
/// the store may not yet be initialized; in those cases this returns
/// `None` so the login still succeeds but the issued token carries no
/// `entity_id` metadata (and therefore fails any `scopes = ["owner"]`
/// check, as it should).
pub(crate) async fn resolve_entity_id(
    core: &dyn VaultCtx,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Option<String> {
    let Some(identity) = core.identity() else {
        // No identity module wired in — common in minimal builds.
        // Log once at WARN so operators noticing missing `entity_id`
        // on tokens have a breadcrumb to follow rather than a
        // silently-disabled feature.
        log::warn!(
            "identity module not loaded — login for {mount}{name} \
             will issue a token without entity_id"
        );
        return None;
    };
    match identity.ensure_entity_id(mount, name, ns_path).await {
        Ok(id) => Some(id),
        Err(e) => {
            log::warn!(
                "entity store get_or_create failed for {mount}{name}: {e}. \
                 Login continues without entity_id."
            );
            None
        }
    }
}

impl UserPassBackend {
    pub fn login_path(&self) -> Path {
        let userpass_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"login/(?P<username>\w[\w-]+\w)",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username of the user."
                },
                "password": {
                    field_type: FieldType::SecretStr,
                    required: true,
                    description: "Password for this user."
                },
                "totp_code": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "TOTP second-factor code (required only when TOTP MFA is enabled for this user)."
                }
            },
            operations: [
                {op: Operation::Write, handler: userpass_backend_ref.login}
            ],
            help: r#"This endpoint authenticates using a username and password (and a TOTP code when MFA is enabled)."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl UserPassBackendInner {
    /// Return `direct` unioned with any policies attached through identity
    /// groups of `kind` that list `member` as a member. On any lookup failure
    /// (module absent, store unavailable, I/O error) falls back to `direct` so
    /// login is never blocked by an optional subsystem.
    pub(crate) async fn expand_identity_group_policies(
        &self,
        kind: GroupKind,
        member: &str,
        direct: &[String],
        ns_path: &str,
    ) -> Vec<String> {
        let Some(identity) = self.core.identity() else {
            return direct.to_vec();
        };
        match identity.expand_group_policies(kind, member, direct, ns_path).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "identity group policy expansion failed for {kind} member '{member}': {e}. \
                     falling back to direct policies only."
                );
                direct.to_vec()
            }
        }
    }

    /// Public entry point: runs the credential check via `login_inner`
    /// and records the outcome (success or failure) to the login-audit
    /// trail so every attempt surfaces on the admin Audit page. The
    /// audit write is best-effort and never blocks or alters the login
    /// result.
    pub async fn login(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let username = req
            .get_data("username")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
            .unwrap_or_else(|| "(unknown)".to_string());
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        let result = self.login_inner(backend, req).await;
        let (success, details) =
            bv_auth_audit::login_outcome(&result);
        bv_auth_audit::record_login(
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

    async fn login_inner(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let err_info = "invalid username or password";
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().unwrap().to_lowercase();
        let password_value = req.get_data("password")?;
        let password = password_value.as_str().unwrap();

        let user = self.get_user(req, &username).await?;
        if user.is_none() {
            log::warn!(target: "security", "userpass login failed: unknown user '{username}'");
            let resp = Response::error_response(err_info);
            return Ok(Some(resp));
        }

        let mut user = user.unwrap();

        // Admin enable/disable switch: a disabled account authenticates by
        // no method (password or FIDO2), whatever the supplied credentials.
        if user.disabled {
            log::warn!(target: "security", "userpass login refused: account '{username}' is disabled");
            return Ok(Some(Response::error_response("account is disabled")));
        }

        // Block password login when FIDO2 is enabled for this user
        if user.fido2_enabled {
            let resp = Response::error_response(
                "Password login is disabled for this account. Use your FIDO2 security key instead.",
            );
            return Ok(Some(resp));
        }

        // Temporary lockout. Refuse while a lock is in force; clear a lock
        // that has already elapsed (plus its counter) before checking the
        // password so the account becomes usable again on this attempt.
        let lockout = self.get_lockout_config(req).await?;
        let now = super::path_users::now_secs();
        if user.locked_until > now {
            let retry = user.locked_until - now;
            log::warn!(target: "security", "userpass login refused: account '{username}' locked for {retry}s");
            return Ok(Some(Response::error_response(&format!(
                "account temporarily locked; try again in {retry} seconds"
            ))));
        }
        if user.locked_until != 0 {
            user.locked_until = 0;
            user.failed_login_count = 0;
            self.set_user(req, &username, &user).await?;
        }

        let check = self.verify_password_hash(password, &user.password_hash)?;
        if !check {
            log::warn!(target: "security", "userpass login failed: bad password for '{username}'");
            self.record_failed_attempt(req, &username, &mut user, &lockout).await?;
            let resp = Response::error_response(err_info);
            return Ok(Some(resp));
        }

        // Second factor. When TOTP MFA is enabled globally *and* for this
        // user, a valid code is mandatory. Fails closed: a missing engine,
        // missing key, or wrong/absent code refuses the login. A failed
        // code feeds the same lockout counter as a bad password so a
        // brute-force of the second factor is throttled too.
        let mfa = self.get_mfa_config(req).await?;
        if mfa.enabled && user.totp_mfa_enabled {
            let code = req
                .get_data("totp_code")
                .ok()
                .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
                .unwrap_or_default();
            if code.is_empty() {
                self.record_failed_attempt(req, &username, &mut user, &lockout).await?;
                return Ok(Some(Response::error_response("a TOTP code is required for this account")));
            }
            let ok = self.verify_totp_mfa(&user, &mfa, &code).await?;
            if !ok {
                log::warn!(target: "security", "userpass login failed: bad TOTP code for '{username}'");
                self.record_failed_attempt(req, &username, &mut user, &lockout).await?;
                return Ok(Some(Response::error_response("invalid TOTP code")));
            }
        }

        // Success: reset the failed-attempt counter / lock if either is set.
        if user.failed_login_count != 0 || user.locked_until != 0 {
            user.failed_login_count = 0;
            user.locked_until = 0;
            self.set_user(req, &username, &user).await?;
        }

        // Multi-tenancy: bind this session to the namespace named by the
        // request header. The credential lives in the root auth mount, but the
        // resulting identity, group expansion, and token are scoped to the login
        // namespace. Fails closed if the header names a namespace that does not
        // exist. With no header the login lands in the principal's first
        // assigned namespace (root when it is unrestricted or assigned root), so
        // a client without a namespace picker can still sign a tenant-only user
        // in instead of dead-ending on the root denial below.
        let (ns_path, ns_uuid) =
            crate::kernel_api::namespace::login_namespace_for_principal(
                &self.core,
                req,
                "userpass/",
                &username,
            )
            .await?;

        // Multi-tenancy: refuse the login if this principal is assigned to a set
        // of namespaces that does not include the login namespace. No assignment
        // record ⇒ unrestricted (fails closed on a non-matching record).
        crate::kernel_api::namespace::enforce_login_assignment(
            &self.core,
            "userpass/",
            &username,
            &ns_path,
        )
        .await?;

        // Union user's direct policies with any policies attached through
        // identity user-groups (of the login namespace) the user is a member of.
        let effective_policies = self
            .expand_identity_group_policies(GroupKind::User, &username, &user.policies, &ns_path)
            .await;

        let mut auth = Auth {
            lease: Lease {
                ttl: user.ttl,
                max_ttl: user.max_ttl,
                renewable: user.ttl.as_secs() > 0,
                ..Default::default()
            },
            display_name: username.to_string(),
            policies: effective_policies.clone(),
            ..Default::default()
        };
        auth.metadata.insert("username".to_string(), username.to_string());
        // Used by policy-templating substitution ({{auth.mount}}).
        auth.metadata.insert("mount_path".to_string(), "userpass/".to_string());
        // Provision / resolve the stable entity_id for this login so
        // ownership-aware ACL rules (`scopes = ["owner"]`) and the KV /
        // resource owner stores can key off the entity rather than the
        // token. Silent on failure — the absence of entity_id just
        // narrows access (owner-scoped rules won't match) rather than
        // blocking login.
        // Quota: refuse a login that would create a *new* entity beyond the
        // namespace's max_entities cap (existing principals are unaffected).
        crate::kernel_api::namespace::check_entity_create(
            &self.core,
            "userpass/",
            &username,
            &ns_path,
        )
        .await?;
        if let Some(entity_id) = resolve_entity_id(&self.core, "userpass/", &username, &ns_path).await {
            auth.metadata.insert("entity_id".to_string(), entity_id);
        }
        // Stamp the namespace binding so the issued token may operate in its
        // login namespace. `child_visible` is not hardcoded off: it follows the
        // login namespace's `child_visible_default` flag, so an operator can opt
        // a namespace (e.g. root) into minting child-visible admin tokens that
        // also reach descendant namespaces without a separate per-namespace
        // login. Default stays false, preserving the strict-isolation baseline.
        let child_visible =
            crate::kernel_api::namespace::login_child_visible(&self.core, &ns_path)
                .await;
        crate::kernel_api::namespace::stamp_binding(
            &mut auth.metadata,
            &ns_path,
            &ns_uuid,
            child_visible,
        );

        // Ensure token_policies mirrors effective policies before
        // populate_token_auth (which overwrites auth.policies with
        // token_policies).
        if user.token_policies.is_empty() && !effective_policies.is_empty() {
            user.token_policies = effective_policies.clone();
        } else if !effective_policies.is_empty() {
            // Add group-derived policies to token_policies if not already present.
            for p in &effective_policies {
                if !user.token_policies.iter().any(|x| x == p) {
                    user.token_policies.push(p.clone());
                }
            }
        }
        user.populate_token_auth(&mut auth);

        // Safety net: if populate_token_auth cleared policies, restore them
        if auth.policies.is_empty() && !effective_policies.is_empty() {
            auth.policies = effective_policies;
        }

        let resp = Response { auth: Some(auth), ..Response::default() };

        Ok(Some(resp))
    }

    /// Increment the failed-attempt counter and, once the lockout policy's
    /// threshold is reached, stamp a lock expiry (and reset the counter so a
    /// post-unlock streak starts fresh). Persists the user. No-op when
    /// lockout is disabled, so `failed_login_count` stays at 0 there.
    async fn record_failed_attempt(
        &self,
        req: &mut Request,
        username: &str,
        user: &mut UserEntry,
        lockout: &LockoutConfig,
    ) -> Result<(), RvError> {
        if !lockout.enabled {
            return Ok(());
        }
        user.failed_login_count = user.failed_login_count.saturating_add(1);
        if lockout.should_lock(user.failed_login_count) {
            let dur = lockout.lockout_duration_secs.max(1) as i64;
            user.locked_until = super::path_users::now_secs() + dur;
            user.failed_login_count = 0;
            log::warn!(
                target: "security",
                "userpass account '{username}' locked for {dur}s after repeated failed attempts"
            );
        }
        self.set_user(req, username, user).await
    }

    /// Validate a submitted TOTP `code` against the key this user is bound
    /// to in the TOTP secret engine. The engine is a sibling mount, so the
    /// shared helper reads its key policy through the router's barrier view
    /// for that mount and runs the RFC 6238 check locally, reusing the
    /// engine's own crypto primitives. Fails closed: an unmounted engine, a
    /// missing/unreadable key, or a malformed policy is an error (login
    /// refused), never a silent bypass.
    ///
    /// The check itself lives in `bastion_vault::modules::totp::mfa` so the
    /// connect-time step-up ceremony validates codes exactly the same way
    /// this login path does — see that module for the note on why the
    /// engine's replay index is not consulted.
    async fn verify_totp_mfa(
        &self,
        user: &UserEntry,
        mfa: &TotpMfaConfig,
        code: &str,
    ) -> Result<bool, RvError> {
        if user.totp_key.trim().is_empty() {
            return Err(RvError::ErrResponse(
                "TOTP MFA is enabled for this account but no TOTP key is bound".to_string(),
            ));
        }
        let totp = self.core.totp_mfa().ok_or_else(|| {
            RvError::ErrResponse(
                "TOTP MFA is enabled for this account but the TOTP engine is not loaded"
                    .to_string(),
            )
        })?;
        let mount = match totp.normalize_mount(&user.totp_mount) {
            m if m.is_empty() => totp.normalize_mount(&mfa.default_mount),
            m => m,
        };

        let now = super::path_users::now_secs().max(0) as u64;
        totp.verify_code(&mount, &user.totp_key, code, now).await
    }

    pub async fn login_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.auth.is_none() {
            return Err(bv_error_string!("invalid request"));
        }
        let mut auth = req.auth.clone().unwrap();
        let username = auth.metadata.get("username");
        if username.is_none() {
            return Ok(None);
        }
        let username = username.unwrap();

        let user = self.get_user(req, username.as_str()).await?;
        if user.is_none() {
            return Ok(None);
        }

        let user = user.unwrap();

        // Compare against the union of user.policies and group-derived
        // policies (scoped to the token's bound namespace), since the login
        // path grants this union.
        let (ns_path, _) =
            crate::kernel_api::namespace::binding_from_metadata(&auth.metadata);
        let effective = self
            .expand_identity_group_policies(GroupKind::User, username, &user.policies, &ns_path)
            .await;
        if !equivalent_policies(&effective, &auth.policies) {
            return Err(bv_error_string!("policies have changed, not renewing"));
        }

        auth.period = user.token_period;
        auth.ttl = user.token_ttl;
        auth.max_ttl = user.token_max_ttl;

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }
}
