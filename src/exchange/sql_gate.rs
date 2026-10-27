//! The `sql_*` rolling-upgrade write gate (features/sql-browser.md §13,
//! decision D4) for the two paths that write policy documents as raw barrier
//! keys, past `PolicyStore`: a `.bvx` exchange import and a BVBK restore.
//! While the gate is closed neither may store a policy naming `sql_*`, so
//! each refuses the whole operation before writing anything. Nothing is
//! stripped: a silently weakened policy is worse than a loud refusal.

use std::str::FromStr;
use std::sync::Arc;

use serde_json::Value;

use crate::{
    core::Core,
    errors::RvError,
    exchange::schema::ExchangeDocument,
    kernel_api::policy::SqlCapability,
    modules::policy::{sql_write_gate::policy_names_sql_capabilities, Policy, PolicyModule, PolicyStore},
};

/// The gate a raw writer consults.
pub enum SqlGate {
    /// The policy store's gate; `None` when the policy module cannot be
    /// reached, which reads as closed.
    Store(Option<Arc<PolicyStore>>),
    /// A fixed answer, for tests of the closed-gate paths (a standalone
    /// vault's gate is open from its first unseal).
    #[cfg(test)]
    Fixed(Result<(), String>),
}

impl SqlGate {
    pub fn of(core: &Core) -> Self {
        let store = core.module_manager().get_module::<PolicyModule>("policy").map(|m| m.policy_store.load_full());
        SqlGate::Store(store)
    }

    /// `Ok` when `sql_*` may be written; may latch the gate open when the
    /// evidence holds, exactly as a policy write does. `Err(reason)` closed.
    pub async fn open_or_reason(&self) -> Result<(), String> {
        match self {
            SqlGate::Store(Some(store)) => store.sql_gate_open_or_reason().await,
            SqlGate::Store(None) => Err("the policy module that holds the SQL write gate is unavailable".into()),
            #[cfg(test)]
            SqlGate::Fixed(r) => r.clone(),
        }
    }

    /// As [`Self::open_or_reason`] without side effects, for a dry run.
    pub async fn writable_now(&self) -> Result<(), String> {
        match self {
            SqlGate::Store(Some(store)) => {
                let status = store.sql_gate_status().await;
                if status.get("sql_capabilities_writable").and_then(Value::as_bool) == Some(true) {
                    Ok(())
                } else {
                    let reason = status.get("reason").and_then(Value::as_str).unwrap_or("the gate is closed");
                    Err(reason.to_string())
                }
            }
            other => other.open_or_reason().await,
        }
    }
}

/// Does a stored policy document (the JSON an export carries, `raw` holding
/// the HCL) name a `sql_*` capability? Parsed as the policy store parses it;
/// a document this node cannot parse is scanned for the eleven names
/// instead, so an unreadable one fails closed.
pub fn policy_document_names_sql(value: &Value) -> bool {
    let raw = value.get("raw").and_then(Value::as_str);
    if let Some(Ok(policy)) = raw.map(Policy::from_str) {
        return policy_names_sql_capabilities(&policy);
    }
    let text = raw.map(str::to_string).unwrap_or_else(|| value.to_string());
    SqlCapability::ALL.iter().any(|c| text.contains(c.as_str()))
}

/// The policies of `document`, root and every namespace bundle, that name
/// `sql_*`, as `name` or `<namespace>/name`.
pub fn sql_policies_in(document: &ExchangeDocument) -> Vec<String> {
    let root = document.items.policies.iter().filter(|p| policy_document_names_sql(&p.value)).map(|p| p.name.clone());
    let bundles = document.items.namespaces.iter().flat_map(|b| {
        b.items
            .policies
            .iter()
            .filter(|p| policy_document_names_sql(&p.value))
            .map(move |p| format!("{}/{}", b.path, p.name))
    });
    root.chain(bundles).collect()
}

fn listed(names: &[String]) -> String {
    let shown: Vec<&str> = names.iter().take(5).map(String::as_str).collect();
    match names.len() {
        n if n > shown.len() => format!("{} (and {} more)", shown.join(", "), n - shown.len()),
        _ => shown.join(", "),
    }
}

/// The refusal of an import carrying `sql_*` policies while the gate is
/// closed.
pub fn import_refused(names: &[String], reason: &str) -> RvError {
    RvError::ErrResponseStatus(
        409,
        format!(
            "this import carries policies naming sql_* capabilities ({}), which cannot be written until every \
             cluster node parses them: {reason}. Nothing was imported; `v2/sys/policy-schema` reports each node \
             (features/sql-browser.md §13)",
            listed(names)
        ),
    )
}

/// The dry-run warning for the same document.
pub fn import_warning(names: &[String], reason: &str) -> String {
    format!(
        "policies naming sql_* capabilities ({}) cannot be written while the SQL write gate is closed ({reason}); \
         the import will be refused",
        listed(names)
    )
}

/// Is `key` a physical key holding a policy document? The root namespace's
/// system view, legacy (`sys/…`) or re-rooted (`namespaces/<uuid>/sys/…`):
/// `policy/`, `policy-rgp/`, `policy-egp/` or a tenant's `policy-ns/<b64>/acl/`.
pub fn is_policy_document_key(key: &str) -> bool {
    let rest = match key.strip_prefix("namespaces/") {
        Some(r) => match r.split_once('/') {
            Some((uuid, rest)) if !uuid.is_empty() => rest,
            _ => return false,
        },
        None => key,
    };
    let Some(sys) = rest.strip_prefix("sys/") else {
        return false;
    };
    for keyspace in ["policy/", "policy-rgp/", "policy-egp/"] {
        if let Some(name) = sys.strip_prefix(keyspace) {
            return !name.is_empty();
        }
    }
    match sys.strip_prefix("policy-ns/").map(|ns| ns.splitn(3, '/').collect::<Vec<_>>()) {
        Some(parts) => matches!(parts.as_slice(), [b64, "acl", name] if !b64.is_empty() && !name.is_empty()),
        None => false,
    }
}

/// The refusal of a BVBK restore carrying policy documents while the gate is
/// closed: their contents are barrier ciphertext, which this path cannot
/// read before writing, so it cannot tell whether any names `sql_*`.
pub fn restore_refused(policies: usize, reason: &str) -> RvError {
    RvError::ErrResponseStatus(
        409,
        format!(
            "this backup carries {policies} policy document(s), which cannot be checked for sql_* capabilities \
             before they are restored, and the SQL write gate is closed: {reason}. Nothing was restored; finish \
             the upgrade until `v2/sys/policy-schema` reports `sql_capabilities_writable`, then restore \
             (features/sql-browser.md §13)"
        ),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_policy_document_is_judged_by_its_parsed_rules() {
        let sql = json!({ "raw": "path \"resources/resources/db/sql/*\" {\n  capabilities = [\"sql_select\"]\n}\n" });
        let plain = json!({ "raw": "path \"secret/*\" {\n  capabilities = [\"read\"]\n}\n" });
        let comment =
            json!({ "raw": "# grants nothing like sql_select\npath \"secret/*\" {\n  capabilities = [\"read\"]\n}\n" });
        assert!(policy_document_names_sql(&sql));
        assert!(!policy_document_names_sql(&plain));
        assert!(!policy_document_names_sql(&comment), "a parsed policy is judged by its rules, not its text");
        // Unparseable here: scanned instead, so it fails closed.
        assert!(policy_document_names_sql(&json!({ "raw": "path { capabilities = [\"sql_drop\"" })));
        assert!(policy_document_names_sql(&json!({ "rules": ["sql_admin"] })));
        assert!(!policy_document_names_sql(&json!({ "raw": "not hcl" })));
    }

    #[test]
    fn policy_document_keys_are_recognised_in_every_layout() {
        for key in [
            "sys/policy/admin",
            "namespaces/7f3e/sys/policy/team/dev",
            "namespaces/7f3e/sys/policy-rgp/r",
            "namespaces/7f3e/sys/policy-egp/e",
            "namespaces/7f3e/sys/policy-ns/dGVuYW50/acl/ops",
        ] {
            assert!(is_policy_document_key(key), "{key}");
        }
        for key in [
            "namespaces/7f3e/sys/policy-schema/sql-gate",
            "namespaces/7f3e/sys/policy-history/admin/0001",
            "namespaces/7f3e/sys/policy-tests/admin",
            "namespaces/7f3e/sys/policy-ns/dGVuYW50/history/ops/1",
            "namespaces/7f3e/logical/abc/sys/policy/x",
            "namespaces//sys/policy/x",
            "sys/policy/",
            "core/mounts",
        ] {
            assert!(!is_policy_document_key(key), "{key}");
        }
    }
}
