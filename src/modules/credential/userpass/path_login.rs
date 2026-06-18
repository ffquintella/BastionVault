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
pub(crate) async fn resolve_entity_id(
    core: &Arc<Core>,
    mount: &str,
    name: &str,
    ns_path: &str,
) -> Option<String> {
    let Some(module) = core
        .module_manager
        .get_module::<IdentityModule>("identity")
    else {
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
    let Some(store) = module.entity_store() else {
        log::warn!(
            "identity entity_store not initialised — login for {mount}{name} \
             will issue a token without entity_id"
        );
        return None;
    };
    match store.get_or_create_entity_ns(mount, name, ns_path).await {
        Ok(entity) => Some(entity.id),
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
        ns_path: &str,
    ) -> Vec<String> {
        let Some(module) = self.core.module_manager.get_module::<IdentityModule>("identity") else {
            return direct.to_vec();
        };
        let Some(store) = module.group_store() else {
            return direct.to_vec();
        };
        match store.expand_policies_ns(kind, member, direct, ns_path).await {
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
            log::warn!(target: "security", "userpass login failed: unknown user '{username}'");
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
            log::warn!(target: "security", "userpass login failed: bad password for '{username}'");
            let resp = Response::error_response(err_info);
            return Ok(Some(resp));
        }

        // Multi-tenancy: bind this session to the namespace named by the
        // request header (root when absent). The credential lives in the
        // root auth mount, but the resulting identity, group expansion, and
        // token are scoped to the login namespace. Fails closed if the header
        // names a namespace that does not exist.
        let (ns_path, ns_uuid) =
            crate::modules::namespace::token_binding::resolve_login_namespace(&self.core, req).await?;

        // Multi-tenancy: refuse the login if this principal is assigned to a set
        // of namespaces that does not include the login namespace. No assignment
        // record ⇒ unrestricted (fails closed on a non-matching record).
        crate::modules::namespace::ns_assignment::enforce_login_assignment(
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
        crate::modules::namespace::quota::check_entity_create(
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
        // login namespace (and only there; child-visible is opt-in elsewhere).
        crate::modules::namespace::token_binding::stamp_binding(
            &mut auth.metadata,
            &ns_path,
            &ns_uuid,
            false,
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
            crate::modules::namespace::token_binding::binding_from_metadata(&auth.metadata);
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
