use std::{collections::HashMap, mem, sync::Arc, time::SystemTime};

use super::{
    path_role::RoleEntry,
    validation::{create_hmac, verify_cidr_role_secret_id_subset},
    AppRoleBackend, AppRoleBackendInner,
};
use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    modules::credential::ferrogate::{machine_id as ferrogate_machine_id, status as ferrogate_status},
    modules::identity::{GroupKind, IdentityModule},
    new_fields, new_fields_internal, new_path, new_path_internal, bv_error_response, bv_error_string,
    storage::StorageEntry,
    utils::cidr,
};

/// Resolve or create the entity_id for an AppRole principal under the
/// `approle/` entity namespace. Returns `None` on any failure so login
/// still succeeds (with no `entity_id` metadata, which means any
/// `scopes = ["owner"]` policy will not match — correct fail-closed
/// behavior).
pub(crate) async fn resolve_approle_entity_id(
    core: &Arc<Core>,
    role_name: &str,
    ns_path: &str,
) -> Option<String> {
    let module = core
        .module_manager
        .get_module::<IdentityModule>("identity")?;
    let store = module.entity_store()?;
    match store.get_or_create_entity_ns("approle/", role_name, ns_path).await {
        Ok(entity) => Some(entity.id),
        Err(e) => {
            log::warn!(
                "entity store unavailable for approle/{role_name}: {e}. \
                 Login continues without entity_id."
            );
            None
        }
    }
}

impl AppRoleBackend {
    pub fn login_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"login$",
            fields: {
                "role_id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Unique identifier of the Role. Required to be supplied when the 'bind_secret_id' constraint is set."
                },
                "secret_id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "SecretID belong to the App role"
                },
                "machine_token": {
                    field_type: FieldType::Str,
                    description: "A live FerroGate machine token bound to the role. Required when the server's approle_require_machine gate is enabled (the default)."
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref.login}
            ],
            help: r#"
While the credential 'role_id' is required at all times,
other credentials required depends on the properties App role
to which the 'role_id' belongs to. The 'bind_secret_id'
constraint (enabled by default) on the App role requires the
'secret_id' credential to be presented.

'role_id' is fetched using the 'role/<role_name>/role_id'
endpoint and 'secret_id' is fetched using the 'role/<role_name>/secret_id'
endpoint."#
        });

        path
    }
}

#[maybe_async::maybe_async]
impl AppRoleBackendInner {
    /// Return `direct` unioned with policies from any identity app-group that
    /// lists `member` as a member. On any error the direct policies are
    /// returned as-is so login is never blocked by an optional subsystem.
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

    /// Public entry point: runs `login_inner` and records the outcome
    /// to the login-audit trail. The `role_id` is an opaque secret, so
    /// the principal is identified by the role name the issued token
    /// carries — known only on success; failed attempts are logged with
    /// `"(unknown)"`. The audit write is best-effort.
    pub async fn login(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let remote_addr = req.connection.as_ref().map(|c| c.peer_addr.clone()).unwrap_or_default();

        let result = self.login_inner(backend, req).await;
        let (success, details) =
            crate::modules::credential::login_audit_store::login_outcome(&result);
        let role_name = match &result {
            Ok(Some(resp)) => resp
                .auth
                .as_ref()
                .and_then(|a| a.metadata.get("role_name"))
                .cloned()
                .unwrap_or_else(|| "(unknown)".to_string()),
            _ => "(unknown)".to_string(),
        };
        crate::modules::credential::login_audit_store::record_login(
            &self.core,
            "approle/",
            &role_name,
            success,
            &remote_addr,
            &details,
        )
        .await;
        result
    }

    async fn login_inner(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_id = req.get_data_as_str("role_id")?;

        let role_id_entry = self.get_role_id(req, &role_id).await?;
        if role_id_entry.is_none() {
            return Err(RvError::ErrResponse("invalid role_id".to_string()));
        }

        let role_id_entry = role_id_entry.unwrap();
        let role_name = role_id_entry.name.clone();

        let role_entry: RoleEntry;
        {
            let lock_entry = self.role_locks.get_lock(&role_name);
            let _locked = lock_entry.lock.read().await;

            role_entry = self
                .get_role(req, &role_id_entry.name)
                .await?
                .ok_or_else(|| RvError::ErrResponse("invalid role_id".to_string()))?;
        }

        let mut metadata: HashMap<String, String> = HashMap::new();

        // Environment scope carried by the secret_id used at login (empty = all).
        let mut secret_envs: Vec<String> = Vec::new();

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());

        if role_entry.bind_secret_id {
            let secret_id = req.get_data_as_str("secret_id")?;

            let secret_id_hmac = create_hmac(&role_entry.hmac_key, &secret_id)?;
            let role_name_hmac = create_hmac(&role_entry.hmac_key, &role_entry.name)?;

            let entry_index = format!("{}{}/{}", &role_entry.secret_id_prefix, &role_name_hmac, &secret_id_hmac);

            let lock_entry = self.secret_id_locks.get_lock(&secret_id_hmac);
            let lock = lock_entry.lock.clone();
            let locked = lock.read_owned().await;

            let secret_id_entry = self
                .get_secret_id_storage_entry(storage, &role_entry.secret_id_prefix, &role_name_hmac, &secret_id_hmac)
                .await?
                .ok_or(RvError::ErrResponse("invalid secret id".to_string()))?;

            // If a secret ID entry does not have a corresponding accessor entry, revoke the secret ID immediately
            let accessor_entry = self
                .get_secret_id_accessor_entry(
                    storage,
                    &secret_id_entry.secret_id_accessor,
                    &role_entry.secret_id_prefix,
                )
                .await?;
            if accessor_entry.is_none() {
                if let Err(err) = storage.delete(&entry_index).await {
                    return Err(RvError::ErrResponse(format!(
                        "error deleting secret_id {} from storage: {}",
                        &secret_id_hmac, err
                    )));
                }

                return Err(RvError::ErrResponse("invalid secret_id".to_string()));
            }

            if secret_id_entry.secret_id_num_uses == 0 {
                // secret_id_num_uses will be zero only if the usage limit was not set at all, in which case,
                // the secret_id will remain to be valid as long as it is not expired.

                // Ensure that the CIDRs on the secret id are still a subset of that of role's
                verify_cidr_role_secret_id_subset(&secret_id_entry.cidr_list, &role_entry.secret_id_bound_cidrs)?;

                if !secret_id_entry.cidr_list.is_empty() {
                    let conn = req
                        .connection
                        .as_ref()
                        .ok_or_else(|| RvError::ErrResponse("failed to get connection information".to_string()))?;
                    if conn.peer_addr.is_empty() {
                        return Err(RvError::ErrResponse("failed to get connection information".to_string()));
                    }

                    let cidr_list_ref: Vec<&str> = secret_id_entry.cidr_list.iter().map(AsRef::as_ref).collect();
                    if !cidr::ip_belongs_to_cidrs(&conn.peer_addr, &cidr_list_ref)? {
                        return Err(RvError::ErrResponse(format!(
                            "source address {} unauthorized through CIDR restrictions on the secret ID",
                            conn.peer_addr
                        )));
                    }
                }
            } else {
                // If the secret_id_num_uses is non-zero, it means that its use-count should be updated in the storage.
                // Switch the lock from a `read` to a `write` and update the storage entry.
                mem::drop(locked);
                let _locked = lock_entry.lock.write().await;

                // Lock switching may change the data. Refresh the contents.
                let mut secret_id_entry = self
                    .get_secret_id_storage_entry(
                        storage,
                        &role_entry.secret_id_prefix,
                        &role_name_hmac,
                        &secret_id_hmac,
                    )
                    .await?
                    .ok_or(RvError::ErrResponse("invalid secret id".to_string()))?;

                // If there exists a single use left, delete the secret_id entry from the storage but do not fail the
                // validation request. Subsequent requests to use the same secret_id will fail.
                if secret_id_entry.secret_id_num_uses == 1 {
                    // Delete the secret IDs accessor first
                    self.delete_secret_id_accessor_entry(
                        storage,
                        &secret_id_entry.secret_id_accessor,
                        &role_entry.secret_id_prefix,
                    )
                    .await?;

                    storage.delete(&entry_index).await?;
                } else {
                    secret_id_entry.secret_id_num_uses -= 1;
                    secret_id_entry.last_updated_time = SystemTime::now();
                    let entry = StorageEntry::new(&entry_index, &secret_id_entry)?;
                    storage.put(&entry).await?;
                }

                // Ensure that the CIDRs on the secret ID are still a subset of that of role's
                verify_cidr_role_secret_id_subset(&secret_id_entry.cidr_list, &role_entry.secret_id_bound_cidrs)?;

                if !secret_id_entry.cidr_list.is_empty() {
                    let conn = req
                        .connection
                        .as_ref()
                        .ok_or_else(|| RvError::ErrResponse("failed to get connection information".to_string()))?;
                    if conn.peer_addr.is_empty() {
                        return Err(RvError::ErrResponse("failed to get connection information".to_string()));
                    }

                    let cidr_list_ref: Vec<&str> = secret_id_entry.cidr_list.iter().map(AsRef::as_ref).collect();
                    if !cidr::ip_belongs_to_cidrs(&conn.peer_addr, &cidr_list_ref)? {
                        return Err(RvError::ErrResponse(format!(
                            "source address {} unauthorized through CIDR restrictions on the secret ID",
                            conn.peer_addr
                        )));
                    }
                }
            }

            secret_envs = secret_id_entry.environments.clone();
            metadata = secret_id_entry.metadata;
        }

        if !role_entry.secret_id_bound_cidrs.is_empty() {
            let conn = req
                .connection
                .as_ref()
                .ok_or_else(|| RvError::ErrResponse("failed to get connection information".to_string()))?;
            if conn.peer_addr.is_empty() {
                return Err(RvError::ErrResponse("failed to get connection information".to_string()));
            }

            let bound_cidrs_ref: Vec<&str> = role_entry.secret_id_bound_cidrs.iter().map(AsRef::as_ref).collect();
            if !cidr::ip_belongs_to_cidrs(&conn.peer_addr, &bound_cidrs_ref)? {
                return Err(RvError::ErrResponse(format!(
                    "source address {} unauthorized by CIDR restrictions on the secret ID",
                    conn.peer_addr
                )));
            }
        }

        // --- Mandatory machine binding ---
        // When the server gate `approle_require_machine` is on (the default),
        // every AppRole login must present a live FerroGate machine token whose
        // machine is bound to this role. The token is proof of an approved
        // machine; we re-check approval (defense in depth) and intersect the
        // machine binding's environment scope with the secret_id's scope.
        // Operators can disable the gate to stage rollout (e.g. before binding
        // machines to existing roles).
        let mut machine_envs: Vec<String> = Vec::new();
        if self.core.approle_require_machine.load(std::sync::atomic::Ordering::Relaxed) {
            let machine_token = req
                .get_data("machine_token")
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| {
                    RvError::ErrResponse(
                        "machine_token is required: AppID logins must present a FerroGate machine token".to_string(),
                    )
                })?;

            let auth_module = self
                .core
                .module_manager
                .get_module::<crate::modules::auth::AuthModule>("auth")
                .ok_or_else(|| RvError::ErrResponse("auth module not loaded".to_string()))?;
            let guard = auth_module.token_store.load();
            let token_store =
                guard.as_ref().ok_or_else(|| RvError::ErrResponse("token store not initialised".to_string()))?;

            let te = match token_store.lookup(&machine_token).await {
                Ok(Some(te)) => te,
                _ => return Err(RvError::ErrResponse("invalid machine_token".to_string())),
            };
            if te.policies.iter().any(|p| p == "root") {
                return Err(RvError::ErrResponse("machine_token cannot be a root token".to_string()));
            }
            if te.meta.get("mount_path").map(String::as_str) != Some("ferrogate/") {
                return Err(RvError::ErrResponse("machine_token is not a FerroGate machine token".to_string()));
            }
            let spiffe_id = te
                .meta
                .get("spiffe_id")
                .cloned()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| RvError::ErrResponse("machine_token lacks a machine identity".to_string()))?;
            let mid = ferrogate_machine_id(&spiffe_id);

            let binding = role_entry
                .bound_machines
                .iter()
                .find(|m| m.machine_id == mid)
                .cloned()
                .ok_or_else(|| {
                    RvError::ErrResponse(format!("machine {spiffe_id} is not bound to role {}", role_entry.name))
                })?;

            // Reject a machine that has since been revoked/rejected. Best-effort:
            // when the FerroGate mount is not readable at the expected path we fall
            // back to trusting the (still-valid) machine token.
            if let Some(m) = self.lookup_ferrogate_machine(&mid).await? {
                if m.status != ferrogate_status::APPROVED {
                    return Err(RvError::ErrResponse(format!(
                        "machine {spiffe_id} is not approved (status={})",
                        m.status
                    )));
                }
            }

            machine_envs = binding.environments.clone();

            // Stamp the machine identity so the issued token is itself machine-bound
            // (satisfies the server `require_machine_identity` gate) and auditable.
            metadata.insert("spiffe_id".to_string(), spiffe_id);
            metadata.insert("machine_id".to_string(), mid);
        }

        // Environment scope on the issued token: enforced by the KV v2 engine.
        // Both the secret_id scope and the machine scope must be satisfied by
        // any `env` request parameter (each empty list = no restriction).
        if !secret_envs.is_empty() || !machine_envs.is_empty() {
            metadata.insert("approle_env_scoped".to_string(), "true".to_string());
            metadata.insert("approle_env_secret".to_string(), secret_envs.join(","));
            metadata.insert("approle_env_machine".to_string(), machine_envs.join(","));
        }

        metadata.insert("role_name".to_string(), role_entry.name.clone());
        metadata.insert("mount_path".to_string(), "approle/".to_string());

        // Multi-tenancy: bind the session to the namespace named by the request
        // header (root when absent). Fails closed on an unknown namespace.
        let (ns_path, ns_uuid) =
            crate::modules::namespace::token_binding::resolve_login_namespace(&self.core, req).await?;

        // Multi-tenancy: refuse the login if this role's namespace assignment
        // does not include the login namespace (no record ⇒ unrestricted; fails
        // closed on a non-matching record).
        crate::modules::namespace::ns_assignment::enforce_login_assignment(
            &self.core,
            "approle/",
            &role_entry.name,
            &ns_path,
        )
        .await?;

        // AppRole sits in its own entity namespace (mount-qualified), further
        // partitioned by the login namespace. An `approle:payments-api` entity
        // in tenant-a is distinct from the same role in tenant-b.
        // Quota: refuse a login that would create a *new* entity beyond the
        // namespace's max_entities cap (existing roles are unaffected).
        crate::modules::namespace::quota::check_entity_create(
            &self.core,
            "approle/",
            &role_entry.name,
            &ns_path,
        )
        .await?;
        if let Some(entity_id) =
            resolve_approle_entity_id(&self.core, &role_entry.name, &ns_path).await
        {
            metadata.insert("entity_id".to_string(), entity_id);
        }

        let mut auth = Auth { metadata, ..Default::default() };
        auth.internal_data.insert("role_name".to_string(), role_entry.name.clone());
        crate::modules::namespace::token_binding::stamp_binding(
            &mut auth.metadata,
            &ns_path,
            &ns_uuid,
            false,
        );

        // Union token_policies with policies attached through identity
        // app-groups (of the login namespace) that list this role as a member.
        let mut effective_role = role_entry.clone();
        effective_role.token_policies = self
            .expand_identity_group_policies(
                GroupKind::App,
                &role_entry.name,
                &role_entry.token_policies,
                &ns_path,
            )
            .await;
        effective_role.populate_token_auth(&mut auth);

        let resp = Response { auth: Some(auth), ..Response::default() };

        Ok(Some(resp))
    }

    pub async fn login_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.auth.is_none() {
            return Err(bv_error_string!("invalid request"));
        }
        let mut auth = req.auth.clone().unwrap();
        let role_name = auth.metadata.get("username");
        if role_name.is_none() {
            return Ok(None);
        }
        let role_name = role_name.unwrap();

        let role = self.get_role(req, role_name.as_str()).await?;
        if role.is_none() {
            return Ok(None);
        }

        let role = self
            .get_role(req, role_name)
            .await?
            .ok_or(bv_error_response!(format!("role {} does not exist during renewal", role_name)))?;

        auth.period = role.token_period;
        auth.ttl = role.token_ttl;
        auth.max_ttl = role.token_max_ttl;

        Ok(Some(Response { auth: Some(auth), ..Response::default() }))
    }
}
