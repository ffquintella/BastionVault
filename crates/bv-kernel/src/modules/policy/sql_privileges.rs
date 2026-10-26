//! `PolicyGate::sql_privileges`: the SQL browser's privilege checks
//! (features/sql-browser.md §3.4). Each check is one capability probe on a
//! synthetic, never-routed path (`<ns>/resources/resources/<r>/sql/…`) by the
//! same `ACL::allow_operation` every request uses, with the qualifiers of
//! `(resource, <r>)` resolved by the helpers `may_connect_target` uses.

use std::collections::HashSet;

use super::{
    acl::ACL,
    policy::Capability,
    policy_store::{resolve_asset_groups, resolve_asset_owner, resolve_target_shared_caps, PolicyStore},
};
use crate::{
    bv_error_response_status, bv_error_string,
    errors::RvError,
    kernel_api::{
        namespace::namespace_header_from_map,
        policy::{canonical_resource, sql_check_path, SqlCheck, SqlPurpose, SqlTarget, SqlVerdict, SQL_MAX_CHECKS},
        VaultCtx,
    },
    logical::{Operation, Request},
    modules::system::denial_audit_store::{record_sql_denials, SqlDenial},
};

#[maybe_async::maybe_async]
impl PolicyStore {
    /// See [`crate::kernel_api::policy::PolicyGate::sql_privileges`].
    ///
    /// Fails closed: a missing caller, an unknown namespace, an unaddressable
    /// resource name, an oversized batch, an unbuildable ACL or any evaluator
    /// error refuses the whole batch with `Err`. Refusals are recorded only
    /// for [`SqlPurpose::Enforce`].
    pub async fn sql_privileges(
        &self,
        req: &Request,
        purpose: SqlPurpose<'_>,
        resource: &str,
        checks: &[SqlCheck],
    ) -> Result<Vec<SqlVerdict>, RvError> {
        let plugin = match purpose {
            SqlPurpose::Enforce { plugin } if !plugin.trim().is_empty() => Some(plugin.trim()),
            SqlPurpose::Enforce { .. } => {
                return Err(bv_error_string!("an enforcing SQL privilege check must name the plugin it is made for"))
            }
            SqlPurpose::Display => None,
        };
        if checks.len() > SQL_MAX_CHECKS {
            return Err(bv_error_response_status!(
                400,
                "too many SQL privilege checks in one batch: {} (at most {})",
                checks.len(),
                SQL_MAX_CHECKS
            ));
        }
        let auth = req.auth.as_ref().ok_or_else(|| bv_error_response_status!(401, "no authenticated caller"))?;
        canonical_resource(resource)?;
        if checks.is_empty() {
            return Ok(Vec::new());
        }
        let core = self.core.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let ns = strict_request_namespace(core.as_ref(), req).await?;
        let ns_opt = if ns.is_empty() { None } else { Some(ns.as_str()) };
        let paths = checks.iter().map(|c| sql_check_path(&ns, resource, &c.target)).collect::<Result<Vec<_>, _>>()?;

        let acl = self.new_acl_for_request(&auth.policies, None, auth, ns_opt).await?;

        let server_path = sql_check_path(&ns, resource, &SqlTarget::Server)?;
        let mut probe = Request::new(server_path.as_str());
        probe.operation = Operation::Read;
        probe.auth = req.auth.clone();
        probe.namespace_path = ns_opt.map(str::to_string);
        probe.api_version = req.api_version;
        // Every check targets `(resource, <r>)`, so the qualifiers are the
        // same for the whole batch: resolve them once. Skipped when no layered
        // rule exists to read them, exactly as `may_connect_target` does.
        if !(acl.grouped_rules.is_empty() && acl.scoped_rules.is_empty()) {
            probe.asset_groups = resolve_asset_groups(&self.core, &server_path, ns_opt).await;
            probe.asset_owner = resolve_asset_owner(&self.core, &server_path, ns_opt).await;
            probe.target_shared_caps = resolve_target_shared_caps(&self.core, &probe).await;
        }

        let verdicts = evaluate_sql_checks(&acl, &mut probe, checks, paths)?;

        if let Some(plugin) = plugin {
            let mut seen = HashSet::new();
            let denials: Vec<SqlDenial<'_>> = verdicts
                .iter()
                .filter(|v| !v.allowed && seen.insert((v.capability, v.path.as_str())))
                .map(|v| SqlDenial { namespace: &ns, path: &v.path, capability: v.capability.as_str(), plugin })
                .collect();
            record_sql_denials(core.as_ref(), req, &denials).await;
        }
        Ok(verdicts)
    }
}

/// Decide each check against `acl`. `probe` carries the caller and the
/// target's resolved qualifiers; `paths[i]` is check `i`'s synthetic path.
///
/// A probe (`check_only`) on a Read op, as `may_connect_target` probes
/// `connect`. The share override makes a `scopes = ["shared"]` rule demand
/// the probed `sql_*` entry on the share, not the `read` a Read implies.
pub(super) fn evaluate_sql_checks(
    acl: &ACL,
    probe: &mut Request,
    checks: &[SqlCheck],
    paths: Vec<String>,
) -> Result<Vec<SqlVerdict>, RvError> {
    let mut verdicts = Vec::with_capacity(checks.len());
    for (check, path) in checks.iter().zip(paths) {
        let cap = Capability::from_sql(check.capability);
        probe.operation = Operation::Read;
        probe.path = path;
        probe.share_capability_override = Some(check.capability.as_str().to_string());
        let r = acl.allow_operation(probe, true)?;
        let denied_by_deny = !r.is_root && r.capabilities_bitmap & Capability::Deny.to_bits() != 0;
        let allowed = r.is_root || (!denied_by_deny && r.capabilities_bitmap & cap.to_bits() != 0);
        verdicts.push(SqlVerdict {
            capability: check.capability,
            target: check.target.clone(),
            path: std::mem::take(&mut probe.path),
            allowed,
            denied_by_deny,
        });
    }
    Ok(verdicts)
}

/// The namespace `req` is addressed to, as a canonical path (`""` = root).
///
/// Stricter than `kernel_api::namespace::caller_namespace`, which reads an
/// unresolvable namespace as root: on an authorization path that would be a
/// silent fallback, so a named namespace that does not resolve is an error.
#[maybe_async::maybe_async]
async fn strict_request_namespace(core: &dyn VaultCtx, req: &Request) -> Result<String, RvError> {
    let raw =
        req.namespace_path.clone().or_else(|| namespace_header_from_map(req.headers.as_ref())).unwrap_or_default();
    let raw = raw.trim().trim_matches('/');
    if raw.is_empty() {
        return Ok(String::new());
    }
    let registry = core
        .namespaces()
        .ok_or_else(|| bv_error_string!("the request names a namespace, but no namespace registry is available"))?;
    match registry.resolve(raw).await? {
        Some(ns) => Ok(ns.path),
        None => Err(bv_error_response_status!(400, "unknown namespace {raw:?} for a SQL privilege check")),
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use super::*;
    use crate::{kernel_api::policy::SqlCapability, logical::Auth, modules::policy::Policy};

    fn acl_of(policies: &[&str]) -> ACL {
        let parsed: Vec<Arc<Policy>> = policies
            .iter()
            .enumerate()
            .map(|(i, text)| {
                let mut p = Policy::from_str(text).unwrap();
                p.name = format!("p{i}");
                Arc::new(p)
            })
            .collect();
        ACL::new(&parsed).unwrap()
    }

    fn default_acl() -> ACL {
        let default = Policy::from_str(super::super::policy_store::DEFAULT_POLICY).unwrap();
        ACL::new(&[Arc::new(default)]).unwrap()
    }

    fn caller(shares: &[&str], groups: &[&str]) -> Request {
        let mut auth = Auth::default();
        auth.metadata.insert("entity_id".into(), "u1".into());
        let mut req = Request::new("resources/resources/db/sql/server");
        req.auth = Some(auth);
        req.asset_owner = "someone-else".into();
        req.target_shared_caps = shares.iter().map(|s| s.to_string()).collect();
        req.asset_groups = groups.iter().map(|s| s.to_string()).collect();
        req
    }

    fn object(c: &str, s: &str, o: &str) -> SqlTarget {
        SqlTarget::Object { catalog: c.into(), schema: s.into(), object: o.into() }
    }

    /// `(capability, target) -> allowed` for `resource` at root.
    fn decide(acl: &ACL, req: &Request, resource: &str, checks: &[(SqlCapability, SqlTarget)]) -> Vec<bool> {
        let checks: Vec<SqlCheck> =
            checks.iter().map(|(c, t)| SqlCheck { capability: *c, target: t.clone() }).collect();
        let paths = checks.iter().map(|c| sql_check_path("", resource, &c.target).unwrap()).collect();
        let mut probe = req.clone();
        evaluate_sql_checks(acl, &mut probe, &checks, paths).unwrap().into_iter().map(|v| v.allowed).collect()
    }

    fn every(target: SqlTarget) -> Vec<(SqlCapability, SqlTarget)> {
        SqlCapability::ALL.iter().map(|c| (*c, target.clone())).collect()
    }

    /// Nothing implies a SQL capability: every ordinary capability on the
    /// resource, `connect` and `sudo` included, grants none of the eleven.
    #[test]
    fn ordinary_capabilities_imply_no_sql_privilege() {
        let acl = acl_of(&[r#"path "resources/*" {
            capabilities = ["create", "read", "update", "delete", "list", "sudo", "patch", "connect"]
        }"#]);
        let req = caller(&[], &[]);
        assert!(decide(&acl, &req, "db", &every(SqlTarget::Server)).iter().all(|a| !a));
        assert!(decide(&acl, &req, "db", &every(object("def", "s", "t"))).iter().all(|a| !a));
    }

    /// No implication between them: each grants only itself.
    #[test]
    fn a_sql_capability_implies_no_other() {
        let req = caller(&[], &[]);
        for granted in SqlCapability::ALL {
            let text = format!("path \"resources/resources/db/sql/*\" {{ capabilities = [\"{granted}\"] }}");
            let acl = acl_of(&[text.as_str()]);
            let got = decide(&acl, &req, "db", &every(SqlTarget::Server));
            for (cap, allowed) in SqlCapability::ALL.iter().zip(got) {
                assert_eq!(allowed, *cap == granted, "{granted} granted, {cap} probed");
            }
        }
    }

    /// The spec's "Support" example (§3.2): a narrower object-scoped rule
    /// governs its schema, the resource-wide one everything else.
    #[test]
    fn object_scoped_rules_narrow_by_path() {
        let acl = acl_of(&[
            r#"path "resources/resources/netrisk-db/sql/*" { capabilities = ["sql_select"] }"#,
            r#"path "resources/resources/netrisk-db/sql/objects/def/netrisk/*" {
                capabilities = ["sql_select", "sql_update", "sql_delete"]
            }"#,
        ]);
        let req = caller(&[], &[]);
        let checks = [
            (SqlCapability::Update, object("def", "netrisk", "users")),
            (SqlCapability::Update, object("def", "other", "users")),
            (SqlCapability::Select, object("def", "other", "users")),
            (SqlCapability::Select, SqlTarget::Server),
            (SqlCapability::Drop, object("def", "netrisk", "users")),
            // Unaddressable: only a grant covering every object applies.
            (SqlCapability::Update, object("def", "netrisk", "a/b")),
            (SqlCapability::Select, object("def", "netrisk", "a/b")),
        ];
        assert_eq!(decide(&acl, &req, "netrisk-db", &checks), [true, false, true, true, false, false, true]);
        // Another resource holds nothing.
        assert_eq!(decide(&acl, &req, "other-db", &checks[..1]), [false]);
    }

    /// `deny` wins: an ungated deny over a share-backed grant, a scoped deny
    /// over an ungated grant, a gated deny over a gated grant.
    #[test]
    fn deny_wins_over_every_sql_grant() {
        let baseline = r#"path "resources/resources/+/sql/*" {
            capabilities = ["sql_select", "sql_drop"]
            scopes = ["shared"]
        }"#;
        let deny = r#"path "resources/resources/pci-db/sql/*" { capabilities = ["deny"] }"#;
        let req = caller(&["sql_select", "sql_drop"], &["prod"]);
        let checks = [(SqlCapability::Select, SqlTarget::Server), (SqlCapability::Drop, object("d", "s", "t"))];
        assert_eq!(decide(&acl_of(&[baseline]), &req, "pci-db", &checks), [true, true], "control");
        assert_eq!(decide(&acl_of(&[baseline, deny]), &req, "pci-db", &checks), [false, false]);

        let ungated = r#"path "resources/resources/pci-db/sql/*" { capabilities = ["sql_select", "sql_drop"] }"#;
        let scoped_deny = r#"path "resources/resources/pci-db/sql/*" {
            capabilities = ["deny"]
            scopes = ["shared"]
        }"#;
        assert_eq!(decide(&acl_of(&[ungated, scoped_deny]), &req, "pci-db", &checks), [false, false]);

        let gated = r#"path "resources/resources/+/sql/*" {
            capabilities = ["sql_select", "sql_drop"]
            groups = ["prod"]
        }"#;
        let gated_deny = r#"path "resources/resources/+/sql/objects/*" {
            capabilities = ["deny"]
            groups = ["prod"]
        }"#;
        assert_eq!(decide(&acl_of(&[gated, gated_deny]), &req, "pci-db", &checks), [true, false]);

        // The verdict says a deny decided it.
        let mut probe = req.clone();
        let check = [SqlCheck { capability: SqlCapability::Select, target: SqlTarget::Server }];
        let paths = vec![sql_check_path("", "pci-db", &SqlTarget::Server).unwrap()];
        let v = evaluate_sql_checks(&acl_of(&[baseline, deny]), &mut probe, &check, paths).unwrap();
        assert!(!v[0].allowed && v[0].denied_by_deny);
    }

    /// The shipped baseline rule is inert without a share, and a share conveys
    /// exactly the `sql_*` entries it names: `read` or `connect` on the share
    /// convey none, and a `sql_select` share conveys no `read`.
    #[test]
    fn the_shared_baseline_conveys_exactly_the_shared_entries() {
        let acl = default_acl();
        let all = every(SqlTarget::Server);

        assert!(decide(&acl, &caller(&[], &[]), "db", &all).iter().all(|a| !a), "no share");
        assert!(decide(&acl, &caller(&["read", "connect", "update"], &[]), "db", &all).iter().all(|a| !a));

        let got = decide(&acl, &caller(&["sql_select", "sql_export"], &[]), "db", &all);
        for ((cap, _), allowed) in all.iter().zip(got) {
            assert_eq!(allowed, matches!(cap, SqlCapability::Select | SqlCapability::Export), "{cap}");
        }

        // A `sql_select` share is not a `read` share: the record stays closed.
        let mut read = caller(&["sql_select"], &[]);
        read.path = "resources/resources/db".into();
        read.operation = Operation::Read;
        assert!(!acl.allow_operation(&read, false).unwrap().allowed);
    }

    /// Ownership grants nothing (§3.3): the owner of the record holds no SQL
    /// privilege through the baseline.
    #[test]
    fn owning_the_record_grants_no_sql_privilege() {
        let mut owner = caller(&[], &[]);
        owner.asset_owner = "u1".into();
        assert!(decide(&default_acl(), &owner, "db", &every(SqlTarget::Server)).iter().all(|a| !a));
    }

    /// The policy tester (`sys/policies/acl/test`) takes capabilities as JSON
    /// strings and explains them with `explain_capability`; `capabilities()`
    /// (behind `sys/capabilities-self`) formats them back.
    #[test]
    fn the_dry_run_and_capabilities_speak_the_sql_names() {
        let acl = acl_of(&[
            r#"path "resources/resources/db/sql/*" { capabilities = ["sql_select", "sql_export"] }"#,
            r#"path "resources/resources/pci/sql/*" { capabilities = ["deny"] }"#,
        ]);
        let select = Capability::from_str("sql_select").unwrap();
        assert!(acl.explain_capability("resources/resources/db/sql/server", select).allowed);
        assert!(!acl.explain_capability("resources/resources/db/sql/server", Capability::SqlDrop).allowed);
        let denied = acl.explain_capability("resources/resources/pci/sql/server", select);
        assert!(!denied.allowed && denied.denied_by_deny);
        assert_eq!(acl.capabilities("resources/resources/db/sql/server"), vec!["sql_select", "sql_export"]);
    }

    /// Only the root token passes everything.
    #[test]
    fn the_root_policy_passes_every_check() {
        let acl = ACL::new(&[Arc::new(Policy { name: "root".into(), ..Default::default() })]).unwrap();
        assert!(decide(&acl, &caller(&[], &[]), "db", &every(object("d", "s", "t"))).iter().all(|a| *a));
    }
}
