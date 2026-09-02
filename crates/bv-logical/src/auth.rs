use std::{collections::HashMap, time::Duration};

use better_default::Default;
use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

use super::lease::Lease;

/// Token metadata key holding the namespace path the token is bound to.
///
/// This and its two siblings key the [`Auth::metadata`] map, which is why
/// they live here and not with the namespace registry that writes them.
/// `kernel_api::namespace` re-exports all three, so the call sites that
/// reach for them through that path are unchanged — but the audit subsystem
/// reads the namespace path off an entry and must not have to name the
/// namespace *engine* to do it. See
/// roadmaps/workspace-decomposition.md § Phase 1.
pub const NS_PATH_META: &str = "namespace_path";

/// Token metadata key holding the namespace uuid the token is bound to.
pub const NS_ID_META: &str = "namespace_id";

/// Token metadata key: may this token see into child namespaces?
pub const CHILD_VISIBLE_META: &str = "child_visible";

/// Token metadata key holding the SPIFFE id of the machine that attested
/// the session. Set only by the FerroGate login handler; its presence is
/// what "machine-bound token" means throughout the kernel.
pub const SPIFFE_ID_META: &str = "spiffe_id";

/// Token metadata key holding the login name of the human principal.
pub const USERNAME_META: &str = "username";

/// Token metadata key holding the stable identity entity id of the human
/// principal.
pub const ENTITY_ID_META: &str = "entity_id";

/// Token metadata keys that only an auth backend may write.
///
/// Everything above the token store reads a token's `meta` map as trusted
/// *input*, not as the caller-supplied annotation the Vault API calls it:
///
/// * [`SPIFFE_ID_META`] is what "machine-bound" means to
///   `machine_identity_satisfied`, i.e. to the server-wide
///   `require_machine_identity` gate;
/// * [`USERNAME_META`], [`ENTITY_ID_META`], `mount_path` and `namespace_*`
///   are substituted into templated policy paths by
///   `policy_store::substitute_path`, so a forged value bends which paths a
///   policy grants;
/// * `mount_path` + `username`/`role_name` name the principal whose
///   operator-authored namespace assignment
///   `namespace::token_binding::assignment_principal` will widen access with;
/// * `approle_env_*` is the AppRole environment scope `bv-engine-kv`'s
///   `enforce_env_scope` applies;
/// * `spiffe_id`, `username` and `entity_id` are also what
///   [`split_principal`] attributes denial- and access-audit records to.
///
/// The rule for the set: **every key an auth backend stamps onto
/// [`Auth::metadata`], plus every key authorization or audit code reads back
/// off it.** Keeping unread keys (`ferrogate_kid`, `name_id`, `subject`) in the
/// list is deliberate — it makes "backend-owned" the property being enforced,
/// so a future reader of one of them is protected on the day it is written
/// rather than the day someone remembers this list.
///
/// # Why this lives in `bv-logical`
///
/// The list has more than one write point, and every one of them is a place
/// where something *outside* the auth backend chooses a metadata key:
///
/// * `auth/token/create` (`bv-kernel`'s token store) copies the request
///   body's `meta` map onto the new token, so a holder of a grant on that
///   path could otherwise mint itself a token that passes the
///   machine-identity gate with no attestation, impersonate another
///   principal in a templated policy, and forge the `machine` and user
///   columns of both audit trails;
/// * the OIDC `claim_mappings` and SAML `attribute_mappings` role fields
///   (`bv-auth-oidc`, `bv-auth-saml`) project an **IdP-controlled** claim
///   value onto an operator-chosen metadata key, which hands the IdP the
///   same forgery if the key is backend-owned.
///
/// Those crates are in different tiers and cannot see each other, so the set
/// lives here — beside the key constants it is built from, which are in this
/// module for the same reason. A second copy would drift, and the two copies
/// would disagree about exactly the keys a gate is read off; that is the
/// failure the shared `machine_identity_satisfied` predicate was introduced
/// to avoid.
///
/// Deliberately *not* the way `machine_identity_exempt` is carried — that one
/// is a typed field on the kernel's token entry for exactly this reason. It
/// is listed here only so a caller who tries the metadata spelling gets an
/// error instead of a token with a meaningless key on it.
pub const RESERVED_TOKEN_META_KEYS: &[&str] = &[
    // Machine identity — the `require_machine_identity` gate.
    SPIFFE_ID_META,
    "machine_id",
    "approle_machine_bypass",
    "machine_identity_exempt",
    // Principal identity — policy templating, audit attribution.
    USERNAME_META,
    ENTITY_ID_META,
    "mount_path",
    "role_name",
    "role",
    "auth_method",
    "groups",
    "subject",
    "name_id",
    "name_id_format",
    "ferrogate_kid",
    "session_id",
    // Namespace binding.
    NS_PATH_META,
    NS_ID_META,
    CHILD_VISIBLE_META,
];

/// Reserved metadata key *prefixes*, for the same reason as
/// [`RESERVED_TOKEN_META_KEYS`].
///
/// `approle_env_` covers the three keys AppRole stamps today
/// (`approle_env_scoped`, `approle_env_secret`, `approle_env_machine`) and any
/// fourth added later, which is the point: an environment scope that a caller
/// can name is an environment scope a caller can rewrite.
pub const RESERVED_TOKEN_META_PREFIXES: &[&str] = &["approle_env_"];

/// Is `key` a backend-owned token metadata key?
///
/// The one predicate every write point asks, so that no call site has to
/// re-implement the prefix half of the rule. See
/// [`RESERVED_TOKEN_META_KEYS`].
pub fn is_reserved_token_meta_key(key: &str) -> bool {
    RESERVED_TOKEN_META_KEYS.contains(&key)
        || RESERVED_TOKEN_META_PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

/// Split a token's identity into `(acting principal, attesting machine)`
/// for the audit trail.
///
/// A FerroGate machine+user session carries the *machine's* SPIFFE id in
/// [`Auth::display_name`] and the bound human's login in the token
/// metadata, so auditing `display_name` alone attributed every action to
/// the machine and never recorded the user. The rule here is:
///
/// * `machine` is the SPIFFE id, or empty for a non-machine-bound token;
/// * `user` is the bound username (falling back to the entity id, which
///   the GUI resolves back to a login) when the token is machine-bound
///   and a user was in fact bound, and the display name otherwise.
///
/// The display-name fallback is deliberate: a machine token with no bound
/// user has no human principal, and the machine *is* the actor, so the
/// SPIFFE id remains the honest answer for "who" — recorded in both
/// fields rather than silently dropped from one.
///
/// Both returned values may be empty; callers own the "(unnamed
/// principal)" style of placeholder, which differs per store.
pub fn split_principal(
    display_name: &str,
    spiffe_id: &str,
    username: &str,
    entity_id: &str,
) -> (String, String) {
    if spiffe_id.is_empty() {
        return (display_name.to_string(), String::new());
    }
    let user = if !username.is_empty() {
        username
    } else if !entity_id.is_empty() {
        entity_id
    } else {
        display_name
    };
    (user.to_string(), spiffe_id.to_string())
}

#[derive(Debug, Clone, Eq, Default, PartialEq, Serialize, Deserialize, Deref, DerefMut)]
pub struct Auth {
    #[deref]
    #[deref_mut]
    pub lease: Lease,

    // ClientToken is the token that is generated for the authentication.
    // This will be filled in by Vault core when an auth structure is returned.
    // Setting this manually will have no effect.
    pub client_token: String,

    // DisplayName is a non-security sensitive identifier that is applicable to this Auth.
    // It is used for logging and prefixing of dynamic secrets. For example,
    // DisplayName may be "armon" for the github credential backend. If the client token
    // is used to generate a SQL credential, the user may be "github-armon-uuid".
    // This is to help identify the source without using audit tables.
    pub display_name: String,

    // Policies is the list of policies that the authenticated user is associated with.
    pub policies: Vec<String>,

    // token_policies break down the list in policies to help determine where a policy was sourced
    #[serde(default)]
    pub token_policies: Vec<String>,

    // Indicates that the default policy should not be added by core when creating a token.
    // The default policy will still be added if it's explicitly defined.
    pub no_default_policy: bool,

    // InternalData is JSON-encodable data that is stored with the auth struct.
    // This will be sent back during a Renew/Revoke for storing internal data used for those operations.
    pub internal_data: HashMap<String, String>,

    // Metadata is used to attach arbitrary string-type metadata to an authenticated user.
    // This metadata will be outputted into the audit log.
    pub metadata: HashMap<String, String>,

    // policy_results is the set of policies that grant the token access to the requesting path.
    pub policy_results: Option<PolicyResults>,

    // period indicates that the token generated using this Auth object should never expire.
    // The token should be renewed within the duration specified by this period.
    pub period: Duration,

    // explicit_max_ttl is the max TTL that constrains periodic tokens. For normal tokens,
    // this value is constrained by the configured max ttl.
    pub explicit_max_ttl: Duration,

    /// Source-address restriction to stamp onto the issued token: the set of
    /// CIDR blocks the token may subsequently be *used* from, in the
    /// canonical string form `SockAddrMarshaler` serializes to.
    ///
    /// Set by an auth backend from its role/user `token_bound_cidrs` (see
    /// `bv_utils::token_util::TokenParams::populate_token_auth`) and copied
    /// onto the token entry by `TokenStore::post_route`. Empty means
    /// unrestricted. This is a restriction on *later* use of the token, not
    /// on the login that mints it — AppRole's `bound_source_ips` and
    /// `secret_id_bound_cidrs` are the login-time checks.
    #[serde(default)]
    pub bound_cidrs: Vec<String>,

    /// Exempts the issued token from the server-wide FerroGate
    /// `require_machine_identity` gate enforced in
    /// `TokenStore::pre_route`.
    ///
    /// Set only by an auth backend that has *already* decided this
    /// principal authenticates without machine attestation -- today that
    /// is AppRole's per-role `bypass_machine_binding`. It is a typed
    /// field rather than a metadata key on purpose: `auth/token/create`
    /// copies its caller-supplied `meta` map onto the new token verbatim,
    /// so keying the exemption on metadata would let any holder of a
    /// grant on that path mint itself an exempt token. Nothing in the
    /// request body maps to this field.
    ///
    /// Copied onto the token entry by `TokenStore::post_route` and
    /// inherited by child tokens (a child can never be more exempt than
    /// its parent).
    #[serde(default)]
    pub machine_identity_exempt: bool,
}

#[derive(Debug, Clone, Eq, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyResults {
    pub allowed: bool,
    pub granting_policies: Vec<PolicyInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub name: String,
    pub namespace_id: String,
    pub namespace_path: String,
    #[serde(rename = "type")]
    #[default("acl".into())]
    pub policy_type: String,
}

#[cfg(test)]
mod tests {
    use super::split_principal;

    #[test]
    fn non_machine_token_keeps_display_name_and_has_no_machine() {
        let (user, machine) = split_principal("felipe", "", "felipe", "e-1");
        assert_eq!(user, "felipe");
        assert_eq!(machine, "");
    }

    #[test]
    fn machine_bound_session_attributes_the_bound_user() {
        let (user, machine) =
            split_principal("ferrogate-spiffe://hml/host/abc", "ferrogate-spiffe://hml/host/abc", "felipe", "e-1");
        assert_eq!(user, "felipe");
        assert_eq!(machine, "ferrogate-spiffe://hml/host/abc");
    }

    #[test]
    fn machine_bound_session_falls_back_to_entity_id() {
        let (user, machine) =
            split_principal("ferrogate-spiffe://hml/host/abc", "ferrogate-spiffe://hml/host/abc", "", "e-1");
        assert_eq!(user, "e-1");
        assert_eq!(machine, "ferrogate-spiffe://hml/host/abc");
    }

    #[test]
    fn unbound_machine_session_reports_the_machine_in_both_fields() {
        let (user, machine) =
            split_principal("ferrogate-spiffe://hml/host/abc", "ferrogate-spiffe://hml/host/abc", "", "");
        assert_eq!(user, "ferrogate-spiffe://hml/host/abc");
        assert_eq!(machine, "ferrogate-spiffe://hml/host/abc");
    }
}

#[cfg(test)]
mod reserved_meta_tests {
    use super::*;

    #[test]
    fn every_key_constant_in_this_module_is_reserved() {
        // The list is built from these constants; this fails if one is
        // renamed out of the list rather than in it.
        for key in [SPIFFE_ID_META, USERNAME_META, ENTITY_ID_META, NS_PATH_META, NS_ID_META, CHILD_VISIBLE_META] {
            assert!(is_reserved_token_meta_key(key), "{key} must be reserved");
        }
    }

    #[test]
    fn approle_env_scope_is_reserved_by_prefix() {
        assert!(is_reserved_token_meta_key("approle_env_scoped"));
        assert!(is_reserved_token_meta_key("approle_env_secret"));
        // The point of the prefix: a key nobody has written yet.
        assert!(is_reserved_token_meta_key("approle_env_something_new"));
    }

    #[test]
    fn free_form_annotations_are_not_reserved() {
        for key in ["email", "department", "requested_by", "ticket", "approle", "usernames", "spiffe"] {
            assert!(!is_reserved_token_meta_key(key), "{key} must stay caller-writable");
        }
    }

    #[test]
    fn reservation_is_exact_not_substring() {
        // `username` is reserved; `username_upn` is a different, free key.
        assert!(is_reserved_token_meta_key(USERNAME_META));
        assert!(!is_reserved_token_meta_key("username_upn"));
    }
}
