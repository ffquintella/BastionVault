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

use std::sync::Arc;

use crate::{bv_error_response_status, core::Core, errors::RvError};

use super::{store::normalize_path, NamespaceModule, NAMESPACE_MODULE_NAME};

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

/// Refuse a policy write whose path rules reference a namespace other than the
/// writer's. No-op for root-scoped writes (`writer_ns_path` empty). Errors with
/// a 403-style error naming the offending path and the namespace it belongs to.
#[maybe_async::maybe_async]
pub async fn refuse_cross_namespace_paths(
    core: &Arc<Core>,
    writer_ns_path: &str,
    paths: &[String],
) -> Result<(), RvError> {
    // Root operator may author policies referencing any tenant.
    if writer_ns_path.is_empty() {
        return Ok(());
    }

    let Some(module) = core.module_manager.get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
    else {
        return Ok(());
    };
    let Some(store) = module.store() else {
        return Ok(());
    };

    // Every existing namespace path (excluding root) is a potential owner.
    let namespaces: Vec<String> = store
        .list_all()
        .await?
        .into_iter()
        .map(|ns| ns.path)
        .filter(|p| !p.is_empty())
        .collect();

    for path in paths {
        let owner = namespace_owner_of_path(path, &namespaces);
        if owner != writer_ns_path {
            let owner_label = if owner.is_empty() { "root".to_string() } else { format!("{owner:?}") };
            return Err(bv_error_response_status!(
                403,
                &format!(
                    "policy in namespace {writer_ns_path:?} may not reference path {path:?} \
                     (belongs to namespace {owner_label}); namespace policies must use \
                     {writer_ns_path:?}-prefixed paths"
                )
            ));
        }
    }
    Ok(())
}

/// Resolve the writer's namespace path from a request's namespace header
/// (canonicalised; empty = root). Used at policy-write time.
pub fn writer_namespace_path(
    headers: Option<&std::collections::HashMap<String, String>>,
) -> String {
    super::router::namespace_header_from_map(headers)
        .and_then(|h| normalize_path(&h).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_owner_of_path() {
        let nss = vec![
            "engineering".to_string(),
            "engineering/platform".to_string(),
            "marketing".to_string(),
        ];
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
}
