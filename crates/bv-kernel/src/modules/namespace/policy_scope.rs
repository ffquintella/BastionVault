//! Namespace policy scoping (Phase 2).
//!
//! This module implements the **cross-namespace path refusal** the spec
//! requires: a policy authored inside namespace `N` may only reference paths
//! that belong to `N`. An `engineering` admin must not be able to write a
//! policy granting access into `marketing`'s path space.
//!
//! ## Path ownership model
//!
//! Namespace mounts are addressed at `<ns_path>/<mount>` in the shared router
//! (see [`super::mount_registry`]); a request scoped to a namespace via the
//! `X-BastionVault-Namespace` header is rewritten to that form before
//! evaluation. Policy ACL rules therefore match these namespaced absolute
//! paths. The *owner* of a policy path is the longest existing-namespace path
//! that is a segment-aligned prefix of it (the root namespace, `""`, owns any
//! path with no such prefix).
//!
//! When a policy is written with a header naming a non-root namespace `N`,
//! every path rule's owner must equal `N`. Root-scoped policy writes (no
//! header) are unrestricted — the root operator manages all tenants.
//!
//! This is a write-time syntactic guard; it does not touch the authorization
//! hot path. (Per-namespace policy *storage* — separate policy documents per
//! namespace — is a larger, separately-reviewed change tracked in the feature
//! file.)
//!
//! One exception (T513): [`NAMESPACE_GRANTABLE_ROUTES`], named exactly. The
//! ACL keeps such a rule only for a token working in the namespace whose
//! policy it is (`PolicyStore::build_acl`).
//!
//! The owner is computed on the parsed path, which loses a prefix rule's `*`;
//! [`rule_within_namespace`] closes that (T519). `.bvx` import re-runs the
//! same check on a namespace's policies ([`check_namespace_policy_rules`], T520),
//! and `PolicyStore::build_acl` keeps, of a stored namespace document, only the
//! rules this predicate confines (backup restore, older builds: T520).

use crate::{bv_error_response_status, errors::RvError, modules::policy::PolicyPathRules};

use super::{NamespaceModule, NAMESPACE_MODULE_NAME};

/// The namespace path that owns `policy_path`: the longest segment-aligned
/// prefix of `policy_path` that is present in `namespaces` (root `""` if none).
pub fn namespace_owner_of_path(policy_path: &str, namespaces: &[String]) -> String {
    // Drop any leading slash and a leading wildcard-only segment edge cases;
    // split on '/'. A trailing "*" stays attached to its final segment, which
    // is fine — we only match whole leading segments against namespace paths.
    let trimmed = policy_path.trim_start_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    for i in (1..=segments.len()).rev() {
        let candidate = segments[..i].join("/");
        if namespaces.iter().any(|n| n == &candidate) {
            return candidate;
        }
    }
    String::new()
}

/// The root-owned paths a namespace policy may name (T513): the namespace
/// transfer, which runs every step as the caller's own request. Exact paths
/// only, never a glob, so no other `sys/` path becomes nameable.
pub const NAMESPACE_GRANTABLE_ROUTES: [&str; 2] = ["sys/namespace-transfer/copy", "sys/namespace-transfer/move"];

/// Whether `path` is one of [`NAMESPACE_GRANTABLE_ROUTES`], byte for byte.
pub fn is_namespace_grantable_route(path: &str) -> bool {
    NAMESPACE_GRANTABLE_ROUTES.contains(&path)
}

/// Whether `rule` names a [`NAMESPACE_GRANTABLE_ROUTES`] path exactly: no
/// trailing `*`, no `+` segment.
pub fn is_namespace_grantable_rule(rule: &PolicyPathRules) -> bool {
    !rule.is_prefix && !rule.has_segment_wildcards && is_namespace_grantable_route(&rule.path)
}

/// Can `rule` match only paths of namespace `ns_path` (T519, T520)? Its path
/// starts with `<ns>/`, or names `<ns>` exactly. A glob ending inside the
/// name (`a*`, parsed as prefix `a`) also matches `ab/...` and `apps/...`.
/// A namespace with a `+` segment confines nothing: a rule reads it as a
/// wildcard. Always true for root, whose policies are unrestricted.
pub fn rule_within_namespace(rule: &PolicyPathRules, ns_path: &str) -> bool {
    if ns_path.is_empty() {
        return true;
    }
    if ns_path.split('/').any(|segment| segment == "+") {
        return false;
    }
    match rule.path.strip_prefix(ns_path) {
        Some(rest) => rest.starts_with('/') || (rest.is_empty() && !rule.is_prefix && !rule.has_segment_wildcards),
        None => false,
    }
}

/// The rule as its author wrote it: the parser keeps a prefix rule's path
/// without its trailing `*`.
fn written_pattern(rule: &PolicyPathRules) -> String {
    if rule.is_prefix {
        format!("{}*", rule.path)
    } else {
        rule.path.clone()
    }
}

/// [`refuse_cross_namespace_paths`] against a known list of every
/// namespace path: also what `.bvx` import re-runs on a namespace's
/// policies (T520). No-op for root (`writer_ns_path` empty).
pub fn check_namespace_policy_rules(
    writer_ns_path: &str,
    rules: &[PolicyPathRules],
    namespaces: &[String],
) -> Result<(), RvError> {
    if writer_ns_path.is_empty() {
        return Ok(());
    }
    for rule in rules.iter().filter(|rule| !is_namespace_grantable_rule(rule)) {
        let path = &rule.path;
        let owner = namespace_owner_of_path(path, namespaces);
        if owner != writer_ns_path {
            let owner_label = if owner.is_empty() { "root".to_string() } else { format!("{owner:?}") };
            return Err(bv_error_response_status!(
                403,
                &format!(
                    "policy in namespace {writer_ns_path:?} may not reference path {path:?} \
                     (belongs to namespace {owner_label}); namespace policies must use \
                     {writer_ns_path:?}-prefixed paths, except the exact paths {:?}",
                    NAMESPACE_GRANTABLE_ROUTES
                )
            ));
        }
        // T519: the owner above is computed on the parsed path, which has lost
        // a prefix rule's `*`; `a*` is owned by `a` yet matches `ab/...`.
        if !rule_within_namespace(rule, writer_ns_path) {
            return Err(bv_error_response_status!(
                403,
                &format!(
                    "policy in namespace {writer_ns_path:?} may not reference path {:?}: it also \
                     matches paths outside the namespace (a sibling namespace or a root mount whose \
                     name starts the same way); use {writer_ns_path:?}-prefixed paths such as \
                     \"{writer_ns_path}/*\", ending a glob only after a full segment",
                    written_pattern(rule)
                )
            ));
        }
    }
    Ok(())
}

/// Every non-root namespace path, or `None` when the namespace module or
/// its store is not installed.
#[maybe_async::maybe_async]
pub async fn namespace_paths(core: &crate::core::Core) -> Result<Option<Vec<String>>, RvError> {
    let Some(module) = core.module_manager().get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME) else {
        return Ok(None);
    };
    let Some(store) = module.store() else {
        return Ok(None);
    };
    Ok(Some(store.list_all().await?.into_iter().map(|ns| ns.path).filter(|p| !p.is_empty()).collect()))
}

/// Refuse a policy write whose path rules reference a namespace other than the
/// writer's, or can match outside it (T519), except a rule naming a
/// [`NAMESPACE_GRANTABLE_ROUTES`] path exactly. No-op for root-scoped writes
/// (`writer_ns_path` empty). Errors with a 403 naming the offending path.
#[maybe_async::maybe_async]
pub async fn refuse_cross_namespace_paths(
    core: &crate::core::Core,
    writer_ns_path: &str,
    rules: &[PolicyPathRules],
) -> Result<(), RvError> {
    // Root operator may author policies referencing any tenant.
    if writer_ns_path.is_empty() {
        return Ok(());
    }
    // Every existing namespace path (excluding root) is a potential owner.
    let Some(namespaces) = namespace_paths(core).await? else {
        return Ok(());
    };
    check_namespace_policy_rules(writer_ns_path, rules, &namespaces)
}

/// Resolve the writer's namespace path from a request's namespace header
/// (canonicalised; empty = root). Used at policy-write time.
pub use crate::kernel_api::namespace::writer_namespace_path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_owner_of_path() {
        let nss = vec!["engineering".to_string(), "engineering/platform".to_string(), "marketing".to_string()];
        // Longest match wins.
        assert_eq!(namespace_owner_of_path("engineering/platform/secret/*", &nss), "engineering/platform");
        assert_eq!(namespace_owner_of_path("engineering/secret/*", &nss), "engineering");
        assert_eq!(namespace_owner_of_path("marketing/kv/foo", &nss), "marketing");
        // No namespace prefix → root.
        assert_eq!(namespace_owner_of_path("secret/*", &nss), "");
        // A path that merely shares a prefix string but not a segment boundary
        // is not owned by that namespace.
        assert_eq!(namespace_owner_of_path("engineering-x/secret", &nss), "");
    }

    /// T513: exactly the two transfer routes, named exactly, are exempt; any
    /// glob, other operation, spelling or `sys/` path is not.
    #[test]
    fn only_the_two_transfer_routes_are_namespace_grantable() {
        use std::str::FromStr;

        use crate::modules::policy::Policy;

        let grantable = |path: &str| {
            let hcl = format!("path \"{path}\" {{ capabilities = [\"update\"] }}");
            let policy = Policy::from_str(&hcl).unwrap();
            is_namespace_grantable_rule(&policy.paths[0])
        };
        for path in ["sys/namespace-transfer/copy", "sys/namespace-transfer/move", "/sys/namespace-transfer/copy"] {
            assert!(grantable(path), "{path}");
        }
        for path in [
            "sys/namespace-transfer/*",
            "sys/namespace-transfer/+",
            "sys/namespace-transfer/copy*",
            "sys/namespace-transfer/copy/*",
            "sys/namespace-transfer/copy/",
            "sys/namespace-transfer",
            "sys/namespace-transfer/",
            "sys/namespace-transfer/delete",
            "sys/namespace-transfer/../mounts",
            "sys/+/copy",
            "+/namespace-transfer/copy",
            "SYS/namespace-transfer/copy",
            "a/sys/namespace-transfer/copy",
            "sys/capabilities-self",
            "sys/policy",
            "sys/*",
            "*",
        ] {
            assert!(!grantable(path), "{path}");
        }
        assert!(!is_namespace_grantable_route("sys/namespace-transfer/copy/"));
        assert!(!is_namespace_grantable_route("/sys/namespace-transfer/copy"));
    }

    fn rule(path: &str) -> PolicyPathRules {
        use std::str::FromStr;
        let hcl = format!("path \"{path}\" {{ capabilities = [\"read\"] }}");
        crate::modules::policy::Policy::from_str(&hcl).unwrap().paths.remove(0)
    }

    /// T519: what a policy in namespace `a` may name, with sibling `ab`,
    /// child `a/b` and an unrelated `apps` present. Every refusal is a 403.
    #[test]
    fn a_namespace_policy_names_only_paths_confined_to_its_namespace() {
        let nss: Vec<String> = ["a", "ab", "a/b", "apps"].iter().map(|s| s.to_string()).collect();
        let check = |path: &str| check_namespace_policy_rules("a", &[rule(path)], &nss);
        for path in [
            "a/*",
            "a/",
            "a",
            "a//x",
            "/a/x",
            "a/secret/*",
            "a/secret/data/x",
            "a/se*",
            "a/+/x",
            "a/{{identity.entity.name}}/*",
            "sys/namespace-transfer/copy",
            "sys/namespace-transfer/move",
        ] {
            assert!(check(path).is_ok(), "{path}: {:?}", check(path));
        }
        for path in [
            "a*", "a**", "/a*", "ab*", "ab/*", "A*", "*", "+/x", "+", "a+", "apps/*", "secret/*", "sys/*", "auth/*",
            "a/b/x", "a/b*", "a/b/*",
        ] {
            match check(path) {
                Err(RvError::ErrResponseStatus(403, m)) => assert!(m.contains("namespace \"a\""), "{path}: {m}"),
                other => panic!("{path}: expected a 403, got {other:?}"),
            }
        }
        let partial = check("a*").unwrap_err().to_string();
        assert!(partial.contains("\"a*\"") && partial.contains("\"a/*\""), "names the glob and the fix: {partial}");
        // Root policies are unrestricted, partial globs included.
        assert!(check_namespace_policy_rules("", &[rule("a*"), rule("sys/*")], &nss).is_ok());
        // A child namespace's own glob stops at its own name as well.
        assert!(check_namespace_policy_rules("a/b", &[rule("a/b/*")], &nss).is_ok());
        assert!(check_namespace_policy_rules("a/b", &[rule("a/b*")], &nss).is_err());
    }

    /// The confinement predicate (T519, T520): `<ns>/` literally, or `<ns>`
    /// exactly; never a partial segment or another spelling of the name.
    #[test]
    fn rule_within_namespace_is_a_literal_segment_prefix() {
        for (path, ns, within) in [
            ("a/*", "a", true),
            ("a/", "a", true),
            ("a", "a", true),
            ("a//x", "a", true),
            ("a/+/x", "a", true),
            ("a/{{request.namespace}}/x", "a", true),
            ("a*", "a", false),
            ("ab*", "a", false),
            ("ab/x", "a", false),
            ("A/x", "a", false),
            ("*", "a", false),
            ("+/x", "a", false),
            ("+", "a", false),
            ("a+", "a", false),
            ("sys/*", "a", false),
            ("{{namespace.path}}/x", "a", false),
            ("a/b/x", "a/b", true),
            ("a/b*", "a/b", false),
            ("a/x", "a/b", false),
            ("t/+/x", "t/+", false),
            ("anything*", "", true),
        ] {
            assert_eq!(rule_within_namespace(&rule(path), ns), within, "{path:?} in {ns:?}");
        }
    }
}
