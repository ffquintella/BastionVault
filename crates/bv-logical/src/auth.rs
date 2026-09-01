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
