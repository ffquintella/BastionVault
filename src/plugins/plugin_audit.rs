//! Plugin `audit_emit` with a host-stamped actor (ABI 1.4,
//! features/sql-browser.md §9.2 and §11). Inside a caller-bound invocation the
//! entry carries the caller's entity, principal, namespace and token HMAC and
//! goes to that namespace's chain. The plugin supplies only the event body.

use serde_json::{Map, Value};

use super::invocation::InvocationCaller;
use super::manifest::PluginManifest;
use crate::{
    audit::{self, AuditEntry},
    kernel_api::VaultCtx,
    logical::{Operation, Request},
};

/// The audit path every plugin event is written under.
pub fn event_path(plugin: &str) -> String {
    format!("sys/plugins/{plugin}/event")
}

/// Whether `manifest`'s events are actor-stamped when a caller is present:
/// ABI minor >= 4 with `caller_identity`. Older plugins keep the actor-less
/// semantics they were built against.
pub fn stamps_actor(manifest: &PluginManifest) -> bool {
    let minor = super::manifest::parse_abi(&manifest.abi_version).map(|(_, m)| m).unwrap_or(0);
    minor >= 4 && manifest.capabilities.caller_identity
}

fn event_body(payload: Value) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("plugin_event".to_string(), payload);
    body
}

/// The entry for one event emitted inside `caller`'s invocation. Who and
/// where come only from `caller`; `payload` lands under the redacted
/// `request.data.plugin_event`, so nothing in it can name the actor.
pub fn stamped_entry(plugin: &str, caller: &Request, payload: Value, hmac_key: &[u8]) -> AuditEntry {
    let mut req = caller.clone();
    req.path = event_path(plugin);
    req.operation = Operation::Write;
    req.body = Some(event_body(payload));
    req.data = None;
    req.mcp_audit = None;
    AuditEntry::from_response(&req, &None, None, hmac_key, false)
}

/// Emit one plugin event: actor-stamped when the invocation has a caller and
/// the plugin is ABI 1.4 with `caller_identity`, otherwise as before (no
/// actor, root chain).
pub async fn emit(
    core: &dyn VaultCtx,
    manifest: &PluginManifest,
    caller: Option<&InvocationCaller>,
    payload: Value,
) {
    let Some(caller) = caller.filter(|_| stamps_actor(manifest)) else {
        audit::emit_sys_audit(
            core,
            "",
            &event_path(&manifest.name),
            Operation::Write,
            Some(event_body(payload)),
            None,
        )
        .await;
        return;
    };
    let Some(broker) = core.audit_broker() else {
        return;
    };
    if !broker.has_devices() {
        return;
    }
    let mut entry = stamped_entry(&manifest.name, caller.request(), payload, broker.hmac_key());
    if let Err(e) = broker.log(&mut entry).await {
        log::warn!("plugin `{}` audit emit failed: {e}", manifest.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logical::Auth;
    use serde_json::json;

    fn caller() -> Request {
        let mut auth = Auth::default();
        auth.display_name = "userpass-alice".into();
        auth.policies = vec!["sql-analyst".into()];
        auth.metadata.insert("entity_id".into(), "ent-alice".into());
        auth.metadata.insert("username".into(), "alice".into());
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.metadata.insert(crate::logical::NS_PATH_META.into(), "dti/esi".into());
        let mut req = Request::new("dbms/v2/sessions");
        req.auth = Some(auth);
        req.client_token = "hvs.alice-token".into();
        req
    }

    /// The plugin cannot set or forge the actor: identity fields in the
    /// payload stay inside the redacted event body.
    #[test]
    fn actor_comes_from_the_caller_not_the_payload() {
        let key = b"audit-hmac-key";
        let forged = json!({
            "event": "dbms.session.open",
            "auth": {"display_name": "root", "metadata": {"entity_id": "attacker"}},
            "namespace": "",
            "entity_id": "attacker",
            "client_token": "forged",
        });
        let e = stamped_entry("dbms-management", &caller(), forged, key);

        assert_eq!(e.namespace, "dti/esi");
        assert_eq!(e.auth.display_name, "userpass-alice");
        assert_eq!(e.auth.metadata["entity_id"], "ent-alice");
        assert_eq!(e.auth.metadata["username"], "alice");
        assert_eq!(e.auth.policies, vec!["sql-analyst".to_string()]);
        let token_hmac = format!("hmac:{}", audit::entry::hmac_redact(key, b"hvs.alice-token"));
        assert_eq!(e.auth.client_token, token_hmac);
        assert_eq!(e.request.path, "sys/plugins/dbms-management/event");

        // Forged identity text exists only as digests inside the body.
        let body = serde_json::to_string(&e.request.data).unwrap();
        assert!(!body.contains("attacker") && !body.contains("forged"), "{body}");
        let whole = serde_json::to_string(&e).unwrap();
        assert!(!whole.contains("hvs.alice-token"));
        assert!(!whole.contains("attacker"));
    }

    #[test]
    fn only_abi_1_4_caller_identity_plugins_are_stamped() {
        let mut m = crate::plugins::sql_grants::tests_support::sql_manifest();
        assert!(stamps_actor(&m));
        m.abi_version = "1.3".into();
        assert!(!stamps_actor(&m));
        m.abi_version = "1.4".into();
        m.capabilities.caller_identity = false;
        assert!(!stamps_actor(&m));
    }
}
