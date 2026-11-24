//! `sys/sso/users[/<mount>/<name>]` (T555): the SSO user directory the OIDC
//! and SAML callbacks fill (store: `bv_auth_audit::sso_users`). ACL-gated like
//! `auth/<mount>/users-info`, root namespace only. HTTP: `/v2/sys` only.

use serde_json::{json, Value};

use super::SystemBackend;
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Backend, Request, Response},
    modules::{
        credential::login_audit_store::sso_users::{normalize_email, SsoUserRecord, SsoUserStore},
        identity::{IdentityModule, UserAuditEntry},
        namespace::router::namespace_header_from_map,
    },
};

/// The API shape of one record. `version` stays internal.
fn record_json(r: &SsoUserRecord) -> Value {
    json!({
        "username": r.username,
        "mount": r.mount,
        "auth_method": r.auth_method,
        "role": r.role,
        "subject": r.subject,
        "email": r.email,
        "email_source": r.email_source,
        "first_login": r.first_login,
        "last_login": r.last_login,
        "login_count": r.login_count,
    })
}

/// The directory spans every tenant, so a namespace-scoped request (which a
/// namespace admin's `sys/*` grant could otherwise satisfy) is refused.
fn require_root_namespace(req: &Request) -> Result<(), RvError> {
    let ns = namespace_header_from_map(req.headers.as_ref()).unwrap_or_default();
    if ns.trim().trim_matches('/').is_empty() {
        Ok(())
    } else {
        Err(bv_error_response_status!(400, "sys/sso/users is deployment-wide; address it from the root namespace"))
    }
}

#[maybe_async::maybe_async]
impl SystemBackend {
    fn sso_user_store(&self) -> Result<SsoUserStore, RvError> {
        SsoUserStore::from_core(&self.core)
    }

    /// `(mount, name)` from the path, `mount` in its trailing-slash form.
    fn sso_user_target(req: &Request) -> Result<(String, String), RvError> {
        let mount = req.get_data_as_str("mount")?;
        let name = req.get_data_as_str("name")?;
        Ok((format!("{}/", mount.trim_end_matches('/')), name))
    }

    /// Best-effort entry on the Admin -> Audit page, as userpass user edits
    /// make. Never fails the request.
    async fn record_sso_user_audit(&self, req: &Request, op: &str, mount: &str, target: &str, details: &str) {
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
        if let Err(e) = store.append(entry).await {
            log::warn!(target: "sso", "sso user directory: user-audit append failed: {e}");
        }
    }

    /// `LIST`/`READ sys/sso/users`: every record, sorted by mount then name.
    pub async fn handle_sso_users_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        require_root_namespace(req)?;
        let records = self.sso_user_store()?.list().await?;
        let keys: Vec<Value> = records.iter().map(|r| Value::String(format!("{}{}", r.mount, r.username))).collect();
        let total = records.len();
        let records: Vec<Value> = records.iter().map(record_json).collect();
        let data = json!({ "keys": keys, "records": records, "total": total }).as_object().cloned();
        Ok(Some(Response::data_response(data)))
    }

    /// `READ sys/sso/users/<mount>/<name>`; 404 when there is no record.
    pub async fn handle_sso_user_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        require_root_namespace(req)?;
        let (mount, name) = Self::sso_user_target(req)?;
        match self.sso_user_store()?.get(&mount, &name).await? {
            Some(r) => Ok(Some(Response::data_response(record_json(&r).as_object().cloned()))),
            None => Err(bv_error_response_status!(404, "no SSO user with that mount and name")),
        }
    }

    /// `WRITE sys/sso/users/<mount>/<name>` `{email}`: set (or, empty, clear)
    /// the e-mail. Only for a principal that has logged in: 404 otherwise.
    pub async fn handle_sso_user_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        require_root_namespace(req)?;
        let (mount, name) = Self::sso_user_target(req)?;
        // Not `get_data_as_str`: it refuses the empty string that clears.
        let Ok(Value::String(email)) = req.get_data("email") else {
            return Err(bv_error_response_status!(400, "email is required (send \"\" to clear it)"));
        };
        if !email.trim().is_empty() && normalize_email(&email).is_none() {
            return Err(bv_error_response_status!(400, "email: not a valid e-mail address"));
        }
        let Some(record) = self.sso_user_store()?.set_email(&mount, &name, &email).await? else {
            return Err(bv_error_response_status!(404, "no SSO user with that mount and name"));
        };
        self.record_sso_user_audit(req, "update", &record.mount, &record.username, "sso user: email").await;
        Ok(Some(Response::data_response(record_json(&record).as_object().cloned())))
    }

    /// `DELETE sys/sso/users/<mount>/<name>`: drop the directory record only.
    /// The namespace assignment (removing it would widen where the principal
    /// may log in) and the identity entity stay. 404 when there is no record.
    pub async fn handle_sso_user_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        require_root_namespace(req)?;
        let (mount, name) = Self::sso_user_target(req)?;
        if !self.sso_user_store()?.delete(&mount, &name).await? {
            return Err(bv_error_response_status!(404, "no SSO user with that mount and name"));
        }
        self.record_sso_user_audit(req, "delete", &mount, &name, "sso user directory record").await;
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
