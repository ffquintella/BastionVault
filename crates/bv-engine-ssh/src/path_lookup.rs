//! `/v1/ssh/lookup` — given an `(ip, username)` pair, return the names
//! of the OTP roles that would mint a credential for it.
//!
//! Useful as a planning / debugging endpoint: callers (or the GUI's
//! "request access" flow) discover which roles cover a target without
//! actually consuming an OTP. CA-mode roles never appear in the
//! result — `lookup` is OTP-specific.

use std::{collections::HashMap, sync::Arc};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{policy::ROLE_PREFIX, SshBackend, SshBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const LOOKUP_HELP: &str = r#"
Find OTP roles that would mint a credential for a given (ip, username).
Returns a list of role names — empty if no role matches. Read-only;
does not generate or consume any OTPs.
"#;

impl SshBackend {
    pub fn lookup_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"lookup",
            fields: {
                "ip": { field_type: FieldType::Str, required: true, description: "Target host IP." },
                "username": { field_type: FieldType::Str, default: "", description: "Login username; empty matches any role with a default_user." }
            },
            operations: [
                {op: Operation::Write, handler: h.handle_lookup}
            ],
            help: LOOKUP_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl SshBackendInner {
    pub async fn handle_lookup(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ip_str = req
            .get_data("ip")?
            .as_str()
            .ok_or_else(|| RvError::ErrString("ip is required".into()))?
            .to_string();
        let ip: std::net::IpAddr = ip_str.parse().map_err(|e| {
            RvError::ErrString(format!("ip `{ip_str}` is not a valid IP address: {e}"))
        })?;
        let username_in = req
            .get_data("username")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        // List all role names, then load each and filter to OTP-mode
        // matches. The role catalog is small (operator-scaled, not
        // user-scaled), so an O(n) scan here is fine — we're not on
        // the per-session hot path.
        let names = req.storage_list(ROLE_PREFIX).await?;
        let mut matches: Vec<String> = Vec::new();
        for name in names {
            // `storage_list` returns just the suffix after the prefix.
            let role = match self.get_role(req, &name).await? {
                Some(r) => r,
                None => continue,
            };
            if role.key_type != "otp" {
                continue;
            }
            if !role.ip_allowed(ip) {
                continue;
            }
            if !username_in.is_empty() {
                // If the caller specified a username, require either an
                // explicit `default_user` match or a wildcard role.
                if role.default_user != username_in
                    && !role.allowed_users_list().iter().any(|u| u == "*" || u == &username_in)
                {
                    continue;
                }
            }
            matches.push(name);
        }
        matches.sort();
        matches.dedup();

        let mut data = Map::new();
        data.insert(
            "roles".into(),
            Value::Array(matches.into_iter().map(Value::String).collect()),
        );
        Ok(Some(Response::data_response(Some(data))))
    }
}
