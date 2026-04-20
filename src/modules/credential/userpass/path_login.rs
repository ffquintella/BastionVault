use std::{collections::HashMap, sync::Arc};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response},
    modules::identity::{GroupKind, IdentityModule},
    new_fields, new_fields_internal, new_path, new_path_internal, bv_error_string,
    utils::policy::equivalent_policies,
};

/// Best-effort resolve-or-create of the entity_id for a principal. The
/// identity module may not be loaded (embedded / minimal builds) or
/// the store may not yet be initialized; in those cases this returns
/// `None` so the login still succeeds but the issued token carries no
/// `entity_id` metadata (and therefore fails any `scopes = ["owner"]`
/// check, as it should).
pub(crate) async fn resolve_entity_id(core: &Arc<Core>, mount: &str, name: &str) -> Option<String> {
    let module = core
        .module_manager
        .get_module::<IdentityModule>("identity")?;
    let store = module.entity_store()?;
    match store.get_or_create_entity(mount, name).await {
        Ok(entity) => Some(entity.id),
        Err(e) => {
            log::warn!(
                "entity store unavailable for {mount}/{name}: {e}. \
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
                }
            },
            operations: [
                {op: Operation::Write, handler: userpass_backend_ref.login}
            ],
            help: r#"This endpoint authenticates using a username and password."#
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
    ) -> Vec<String> {
        let Some(module) = self.core.module_manager.get_module::<IdentityModule>("identity") else {
            return direct.to_vec();
        };
        let Some(store) = module.group_store() else {
            return direct.to_vec();
        };
        match store.expand_policies(kind, member, direct).await {
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

    pub async fn login(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let err_info = "invalid username or password";
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().unwrap().to_lowercase();
        let password_value = req.get_data("password")?;
        let password = password_value.as_str().unwrap();

        let user = self.get_user(req, &username).await?;
        if user.is_none() {
            log::error!("{err_info}");
            let resp = Response::error_response(err_info);
            return Ok(Some(resp));
        }

        let mut user = user.unwrap();

        // Block password login when FIDO2 is enabled for this user
        if user.fido2_enabled {
            let resp = Response::error_response(
                "Password login is disabled for this account. Use your FIDO2 security key instead.",
            );
            return Ok(Some(resp));
        }

        let check = self.verify_password_hash(password, &user.password_hash)?;
        if !check {
            log::error!("{err_info}");
            let resp = Response::error_response(err_info);
            return Ok(Some(resp));
        }

        // Union user's direct policies with any policies attached through
        // identity user-groups the user is a member of.
        let effective_policies = self
            .expand_identity_group_policies(GroupKind::User, &username, &user.policies)
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
        // Provision / resolve the stable entity_id for this login so
        // ownership-aware ACL rules (`scopes = ["owner"]`) and the KV /
        // resource owner stores can key off the entity rather than the
        // token. Silent on failure — the absence of entity_id just
        // narrows access (owner-scoped rules won't match) rather than
        // blocking login.
        if let Some(entity_id) = resolve_entity_id(&self.core, "userpass/", &username).await {
            auth.metadata.insert("entity_id".to_string(), entity_id);
        }

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
        // policies, since the login path grants this union.
        let effective = self
            .expand_identity_group_policies(GroupKind::User, username, &user.policies)
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
