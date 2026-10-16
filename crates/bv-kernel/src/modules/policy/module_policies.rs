//! Per-module baseline policies: `<module>-full`, `-read`, `-connect`, `-shared`,
//! each scoped to the namespace a request addresses. What each variant grants,
//! and why siblings repeat path strings: `features/module-policies.md`.

/// Token self-service and the private cubbyhole, so each policy is usable on
/// its own. Identical to `administrator`'s restatement, so it merges.
macro_rules! self_service {
    () => {
        r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }
"#
    };
}

/// Opt in to shares whose grantee is an identity group the caller belongs to;
/// without it group shares are filtered out of the ACL and the share feed.
macro_rules! group_shares {
    () => {
        r#"
metadata {
    group_shared_resources = "true"
}
"#
    };
}

// --- secrets (KV, `secret/`) ------------------------------------------------

pub(crate) const SECRETS_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#
);

pub(crate) const SECRETS_READ: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/secret/*" {
    capabilities = ["read", "list"]
}
"#
);

pub(crate) const SECRETS_SHARED: &str = concat!(
    self_service!(),
    r#"
# Share-scoped only: a rule contributes access solely when an active share for
# (target, caller) carries the capability the operation maps to.
path "{{request.namespace}}/secret/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "{{request.namespace}}/secret/data/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "{{request.namespace}}/secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["shared"]
}
"#,
    group_shares!()
);

// --- resource (`resources/` + asset groups in `resource-group/`) ------------

pub(crate) const RESOURCE_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/resources/*" {
    capabilities = ["create", "read", "update", "delete", "list", "connect"]
}
path "{{request.namespace}}/resources/secrets/*" {
    capabilities = ["create", "read", "update", "delete", "list", "connect"]
}
path "{{request.namespace}}/resource-group/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/resource-group/groups" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Restated from `resource-connect` / `resource-shared` so holding either next
# to this policy cannot narrow it.
path "{{request.namespace}}/resources/v2/connect/mfa/begin"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/mfa/verify" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/authorize"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/provider/candidates" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/providers"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/web/launch" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/web/totp"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/web/result" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/web/close"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/resources/v2/connect/clipboard/audit" { capabilities = ["create", "read", "update", "delete", "list"] }
path "rustion/session/open"    { capabilities = ["update"] }
path "rustion/v2/session/open" { capabilities = ["update"] }
path "rustion/session/renew"   { capabilities = ["update"] }
path "rustion/session/kill"    { capabilities = ["update"] }
"#
);

pub(crate) const RESOURCE_READ: &str = concat!(
    self_service!(),
    r#"
# Resource records and their per-resource secrets. Opening sessions is
# `resource-connect`'s.
path "{{request.namespace}}/resources/*" {
    capabilities = ["read", "list"]
}
path "{{request.namespace}}/resources/secrets/*" {
    capabilities = ["read", "list"]
}
path "{{request.namespace}}/resource-group/*" {
    capabilities = ["read", "list"]
}
path "{{request.namespace}}/resource-group/groups" {
    capabilities = ["read", "list"]
}
"#
);

pub(crate) const RESOURCE_CONNECT: &str = concat!(
    self_service!(),
    r#"
# See the records (the client reads one to dial it) and open sessions as their
# credentials without reading them: `connect` without `read` on
# `resources/secrets/<name>/` is what `PolicyStore::may_connect_target` checks.
path "{{request.namespace}}/resources/*" {
    capabilities = ["read", "list"]
}
path "{{request.namespace}}/resources/secrets/*" {
    capabilities = ["connect"]
}
path "{{request.namespace}}/resource-group/*" {
    capabilities = ["read", "list"]
}
path "{{request.namespace}}/resource-group/groups" {
    capabilities = ["read", "list"]
}

# Connect-time gates, endpoint-level: each handler re-authorizes the resource
# named in the body through `may_connect_target`.
path "{{request.namespace}}/resources/v2/connect/mfa/begin"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/mfa/verify" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/authorize"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/provider/candidates" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/providers"  { capabilities = ["read"] }
path "{{request.namespace}}/resources/v2/connect/web/launch" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/totp"   { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/result" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/close"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/clipboard/audit" { capabilities = ["update"] }

# Bastion sessions. `rustion/` is header-scoped, so these are bare. Both open
# endpoints run their own per-resource check; the unbound v1 shape also needs
# `sudo`, which is not granted here.
path "rustion/session/open"    { capabilities = ["update"] }
path "rustion/v2/session/open" { capabilities = ["update"] }
path "rustion/session/renew"   { capabilities = ["update"] }
path "rustion/session/kill"    { capabilities = ["update"] }
"#
);

pub(crate) const RESOURCE_SHARED: &str = concat!(
    self_service!(),
    r#"
# Resources shared with the caller. `connect` is never inferred from `read`:
# the scope gate demands `connect` on the share itself.
path "{{request.namespace}}/resources/*" {
    capabilities = ["read", "list", "update", "connect"]
    scopes       = ["shared"]
}

# Asset groups: the list is ungated (the handler narrows it to groups the
# caller owns or was shared on); reading one is share-scoped.
path "{{request.namespace}}/resource-group/groups" {
    capabilities = ["list"]
}
path "{{request.namespace}}/resource-group/groups/+" {
    capabilities = ["read"]
    scopes       = ["shared"]
}

path "{{request.namespace}}/resources/v2/connect/mfa/begin"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/mfa/verify" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/authorize"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/provider/candidates" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/providers"  { capabilities = ["read"] }
path "{{request.namespace}}/resources/v2/connect/web/launch" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/totp"   { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/result" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/web/close"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/clipboard/audit" { capabilities = ["update"] }
path "rustion/session/open"    { capabilities = ["update"] }
path "rustion/v2/session/open" { capabilities = ["update"] }
path "rustion/session/renew"   { capabilities = ["update"] }
path "rustion/session/kill"    { capabilities = ["update"] }
"#,
    group_shares!()
);

// --- files (`files/`) ---------------------------------------------------------

pub(crate) const FILES_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/files/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#
);

pub(crate) const FILES_READ: &str = concat!(
    self_service!(),
    r#"
# Metadata, content, history and versions. No sync push, no restore.
path "{{request.namespace}}/files/*" {
    capabilities = ["read", "list"]
}
"#
);

pub(crate) const FILES_SHARED: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/files/files/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
"#,
    group_shares!()
);

// --- ssh (SSH CA + OTP, `ssh/`) -----------------------------------------------

pub(crate) const SSH_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/ssh/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/ssh/roles"      { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/roles/+"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/roles-info" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/config/ca"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/public_key" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/sign/+"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/creds/+"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/ssh/lookup"     { capabilities = ["create", "read", "update", "delete", "list"] }
"#
);

pub(crate) const SSH_READ: &str = concat!(
    self_service!(),
    r#"
# Roles and the CA's public key. Never a signed certificate or an OTP.
path "{{request.namespace}}/ssh/roles"      { capabilities = ["list"] }
path "{{request.namespace}}/ssh/roles/+"    { capabilities = ["read"] }
path "{{request.namespace}}/ssh/roles-info" { capabilities = ["read"] }
path "{{request.namespace}}/ssh/config/ca"  { capabilities = ["read"] }
path "{{request.namespace}}/ssh/public_key" { capabilities = ["read"] }
"#
);

pub(crate) const SSH_CONNECT: &str = concat!(
    self_service!(),
    r#"
# Pick a role, then get a certificate signed or an OTP minted for it. The
# role's own constraints (principals, TTL, CIDRs) still bind the result.
path "{{request.namespace}}/ssh/roles"   { capabilities = ["list"] }
path "{{request.namespace}}/ssh/sign/+"  { capabilities = ["create", "update"] }
path "{{request.namespace}}/ssh/creds/+" { capabilities = ["create", "update"] }
path "{{request.namespace}}/ssh/lookup"  { capabilities = ["update"] }
"#
);

// --- pki (`pki/`) -------------------------------------------------------------

pub(crate) const PKI_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/pki/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/pki/ca"             { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/ca/pem"         { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/ca_chain"       { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/cert/+"         { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/certs"          { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/certs-info"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/crl"            { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/crl/pem"        { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issuers"        { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issuer/+"       { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issuer/+/chain" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issuer/+/crl"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issuer/+/crl/pem" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/roles"          { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/roles/+"        { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/issue/+"        { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/pki/sign/+"         { capabilities = ["create", "read", "update", "delete", "list"] }
"#
);

pub(crate) const PKI_READ: &str = concat!(
    self_service!(),
    r#"
# Public material and inventory only. Absent on purpose: `cert/<serial>/key`,
# `cert/<serial>/export`, `issuer/<ref>/export`, `key/<ref>` and `keys`, the
# paths that return or enumerate private keys.
path "{{request.namespace}}/pki/ca"             { capabilities = ["read"] }
path "{{request.namespace}}/pki/ca/pem"         { capabilities = ["read"] }
path "{{request.namespace}}/pki/ca_chain"       { capabilities = ["read"] }
path "{{request.namespace}}/pki/cert/+"         { capabilities = ["read"] }
path "{{request.namespace}}/pki/certs"          { capabilities = ["list"] }
path "{{request.namespace}}/pki/certs-info"     { capabilities = ["read"] }
path "{{request.namespace}}/pki/crl"            { capabilities = ["read"] }
path "{{request.namespace}}/pki/crl/pem"        { capabilities = ["read"] }
path "{{request.namespace}}/pki/issuers"        { capabilities = ["read", "list"] }
path "{{request.namespace}}/pki/issuer/+"       { capabilities = ["read"] }
path "{{request.namespace}}/pki/issuer/+/chain" { capabilities = ["read"] }
path "{{request.namespace}}/pki/issuer/+/crl"   { capabilities = ["read"] }
path "{{request.namespace}}/pki/issuer/+/crl/pem" { capabilities = ["read"] }
path "{{request.namespace}}/pki/roles"          { capabilities = ["list"] }
path "{{request.namespace}}/pki/roles/+"        { capabilities = ["read"] }
"#
);

pub(crate) const PKI_CONNECT: &str = concat!(
    self_service!(),
    r#"
# Issue and sign against a role, bound by that role's constraints.
# `sign-verbatim` bypasses role constraints, so it stays with `pki-full`.
path "{{request.namespace}}/pki/roles"   { capabilities = ["list"] }
path "{{request.namespace}}/pki/issue/+" { capabilities = ["create", "update"] }
path "{{request.namespace}}/pki/sign/+"  { capabilities = ["create", "update"] }
"#
);

// --- ad (OpenLDAP / Active Directory, `openldap/`) ----------------------------

pub(crate) const AD_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/openldap/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/openldap/static-role"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/static-role/+" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/static-cred/+" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/library"       { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/library/+"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/library/+/status"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/library/+/check-out" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/openldap/library/+/check-in"  { capabilities = ["create", "read", "update", "delete", "list"] }
"#
);

pub(crate) const AD_READ: &str = concat!(
    self_service!(),
    r#"
# Role and library definitions plus check-out status. Never a password:
# `static-cred` is `ad-connect`'s and `config` (the bind credential) `ad-full`'s.
path "{{request.namespace}}/openldap/static-role"   { capabilities = ["list"] }
path "{{request.namespace}}/openldap/static-role/+" { capabilities = ["read"] }
path "{{request.namespace}}/openldap/library"       { capabilities = ["list"] }
path "{{request.namespace}}/openldap/library/+"     { capabilities = ["read"] }
path "{{request.namespace}}/openldap/library/+/status" { capabilities = ["read"] }
"#
);

pub(crate) const AD_CONNECT: &str = concat!(
    self_service!(),
    r#"
# Use the managed accounts: read a static role's current password, check
# library accounts out and in. Forced rotation stays with `ad-full`.
path "{{request.namespace}}/openldap/static-role"   { capabilities = ["list"] }
path "{{request.namespace}}/openldap/static-cred/+" { capabilities = ["read"] }
path "{{request.namespace}}/openldap/library"       { capabilities = ["list"] }
path "{{request.namespace}}/openldap/library/+/check-out" { capabilities = ["create", "update"] }
path "{{request.namespace}}/openldap/library/+/check-in"  { capabilities = ["create", "update"] }
"#
);

// --- totp (`totp/`) -----------------------------------------------------------

pub(crate) const TOTP_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/totp/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/totp/keys"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/totp/keys/+" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/totp/code/+" { capabilities = ["create", "read", "update", "delete", "list"] }
"#
);

pub(crate) const TOTP_READ: &str = concat!(
    self_service!(),
    r#"
# Key names and metadata. The seed is never returned after creation; a code
# is `totp-connect`'s.
path "{{request.namespace}}/totp/keys"   { capabilities = ["list"] }
path "{{request.namespace}}/totp/keys/+" { capabilities = ["read"] }
"#
);

pub(crate) const TOTP_CONNECT: &str = concat!(
    self_service!(),
    r#"
# Fetch a generate-mode code, or validate a provider-mode one.
path "{{request.namespace}}/totp/keys"   { capabilities = ["list"] }
path "{{request.namespace}}/totp/code/+" { capabilities = ["create", "read", "update"] }
"#
);

// --- transit (`transit/`) -----------------------------------------------------

pub(crate) const TRANSIT_FULL: &str = concat!(
    self_service!(),
    r#"
path "{{request.namespace}}/transit/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "{{request.namespace}}/transit/keys"      { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/keys/+"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/encrypt/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/decrypt/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/rewrap/*"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/sign/*"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/verify/*"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/hmac/*"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/datakey/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/random"    { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/random/*"  { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/hash"      { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{request.namespace}}/transit/hash/*"    { capabilities = ["create", "read", "update", "delete", "list"] }
"#
);

pub(crate) const TRANSIT_READ: &str = concat!(
    self_service!(),
    r#"
# Key names and public metadata (version table, public keys for verify).
# `keys/+` does not reach `keys/<name>/rotate|config|trim|import`.
path "{{request.namespace}}/transit/keys"   { capabilities = ["list"] }
path "{{request.namespace}}/transit/keys/+" { capabilities = ["read"] }
"#
);

pub(crate) const TRANSIT_CONNECT: &str = concat!(
    self_service!(),
    r#"
# Cryptographic operations with existing keys. No key lifecycle.
path "{{request.namespace}}/transit/keys"      { capabilities = ["list"] }
path "{{request.namespace}}/transit/encrypt/*" { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/decrypt/*" { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/rewrap/*"  { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/sign/*"    { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/verify/*"  { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/hmac/*"    { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/datakey/*" { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/random"    { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/random/*"  { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/hash"      { capabilities = ["create", "update"] }
path "{{request.namespace}}/transit/hash/*"    { capabilities = ["create", "update"] }
"#
);

/// Every per-module baseline as `(name, hcl)`, grouped by module in `full`,
/// `read`, `connect`, `shared` order. The loader seeds exactly this list.
pub(crate) const MODULE_POLICIES: &[(&str, &str)] = &[
    ("secrets-full", SECRETS_FULL),
    ("secrets-read", SECRETS_READ),
    ("secrets-shared", SECRETS_SHARED),
    ("resource-full", RESOURCE_FULL),
    ("resource-read", RESOURCE_READ),
    ("resource-connect", RESOURCE_CONNECT),
    ("resource-shared", RESOURCE_SHARED),
    ("files-full", FILES_FULL),
    ("files-read", FILES_READ),
    ("files-shared", FILES_SHARED),
    ("ssh-full", SSH_FULL),
    ("ssh-read", SSH_READ),
    ("ssh-connect", SSH_CONNECT),
    ("pki-full", PKI_FULL),
    ("pki-read", PKI_READ),
    ("pki-connect", PKI_CONNECT),
    ("ad-full", AD_FULL),
    ("ad-read", AD_READ),
    ("ad-connect", AD_CONNECT),
    ("totp-full", TOTP_FULL),
    ("totp-read", TOTP_READ),
    ("totp-connect", TOTP_CONNECT),
    ("transit-full", TRANSIT_FULL),
    ("transit-read", TRANSIT_READ),
    ("transit-connect", TRANSIT_CONNECT),
];

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr, sync::Arc};

    use super::*;
    use crate::modules::policy::{acl::ACL, policy::Policy, policy_store::DEFAULT_POLICY};

    const NS: &str = "{{request.namespace}}/";

    /// Render a policy as `apply_templates` does for a request addressed to
    /// `ns` (`""` = root, separator swallowed).
    fn render(hcl: &str, ns: &str) -> String {
        if ns.is_empty() {
            hcl.replace(NS, "")
        } else {
            hcl.replace(NS, &format!("{ns}/"))
        }
    }

    fn acl_of(hcls: &[&str], ns: &str) -> ACL {
        let policies: Vec<Arc<Policy>> = hcls
            .iter()
            .map(|h| Arc::new(Policy::from_str(&render(h, ns)).expect("built-in policy must parse")))
            .collect();
        ACL::new(&policies).expect("ACL must build")
    }

    /// Ungated capabilities the ACL grants on `path` (empty = none).
    fn caps(acl: &ACL, path: &str) -> BTreeSet<String> {
        acl.capabilities(path.to_string()).into_iter().filter(|c| c != "deny").collect()
    }

    fn policy(name: &str) -> &'static str {
        MODULE_POLICIES.iter().find(|(n, _)| *n == name).map(|(_, h)| *h).expect("known policy")
    }

    fn module_of(name: &str) -> &str {
        name.rsplit_once('-').map(|(m, _)| m).unwrap()
    }

    fn modules() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for (n, _) in MODULE_POLICIES {
            let m = n.rsplit_once('-').unwrap().0;
            if !out.contains(&m) {
                out.push(m);
            }
        }
        out
    }

    fn family(module: &str) -> Vec<(&'static str, &'static str)> {
        MODULE_POLICIES.iter().filter(|(n, _)| module_of(n) == module).copied().collect()
    }

    /// Concrete request paths exercising every rule of a module's policies:
    /// each rule path with `+` and a trailing `*` instantiated, plus the
    /// prefix a trailing `*` hangs off.
    fn probes(module: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (name, hcl) in family(module) {
            let p = Policy::from_str(&render(hcl, "")).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            for r in &p.paths {
                let concrete = r.path.replace('+', "x");
                if let Some(prefix) = concrete.strip_suffix('*') {
                    out.insert(prefix.to_string());
                    out.insert(format!("{prefix}x"));
                    out.insert(format!("{prefix}x/y"));
                } else {
                    out.insert(concrete);
                }
            }
        }
        out
    }

    #[test]
    fn every_module_policy_parses_and_is_named_by_family() {
        let mut names = BTreeSet::new();
        for (name, hcl) in MODULE_POLICIES {
            assert!(names.insert(*name), "{name} listed twice");
            let suffix = name.rsplit_once('-').unwrap().1;
            assert!(matches!(suffix, "full" | "read" | "connect" | "shared"), "{name}: unknown variant");
            Policy::from_str(hcl).unwrap_or_else(|e| panic!("{name} must parse: {e:?}"));
        }
        for m in modules() {
            assert!(names.contains(format!("{m}-full").as_str()), "{m} has no -full");
            assert!(names.contains(format!("{m}-read").as_str()), "{m} has no -read");
        }
    }

    /// The new names must not shadow a baseline the store already seeds.
    #[test]
    fn module_policy_names_do_not_collide_with_older_baselines() {
        for old in [
            "default",
            "administrator",
            "standard-user",
            "standard-user-readonly",
            "secret-author",
            "shared-access",
            "pki-user",
            "pki-admin",
            "totp-user",
            "totp-admin",
            "transit-user",
            "transit-admin",
            "ldap-user",
            "ldap-admin",
            "root",
        ] {
            assert!(MODULE_POLICIES.iter().all(|(n, _)| *n != old), "{old} reused");
        }
    }

    /// Every object rule is namespace-templated; only self-service and the
    /// header-scoped `rustion/` session endpoints are bare.
    #[test]
    fn object_rules_are_scoped_to_the_request_namespace() {
        for (name, hcl) in MODULE_POLICIES {
            let p = Policy::from_str(hcl).unwrap();
            for r in &p.paths {
                let bare_ok = r.path.starts_with("auth/token/")
                    || r.path == "sys/capabilities-self"
                    || r.path == "sys/internal/ui/resultant-acl"
                    || r.path.starts_with("cubbyhole/")
                    || r.path.starts_with("rustion/session/")
                    || r.path.starts_with("rustion/v2/session/");
                assert!(bare_ok || r.path.starts_with(NS), "{name}: `{}` must use the request namespace", r.path);
                assert!(!r.path.contains("{{namespace.path}}"), "{name}: use the request namespace");
            }
        }
    }

    /// The property the shared-path-string discipline exists for: carrying
    /// more of a module's policies (alongside `default`, which every login
    /// carries) never removes a capability any one of them grants alone.
    #[test]
    fn adding_a_variant_never_removes_access() {
        for module in modules() {
            let fam = family(module);
            let probes = probes(module);
            for mask in 1u32..(1 << fam.len()) {
                let held: Vec<(&str, &str)> =
                    fam.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, p)| *p).collect();
                let mut hcls = vec![DEFAULT_POLICY];
                hcls.extend(held.iter().map(|(_, h)| *h));
                let combined = acl_of(&hcls, "");
                let names: Vec<&str> = held.iter().map(|(n, _)| *n).collect();
                for (_, single) in &held {
                    let alone = acl_of(&[DEFAULT_POLICY, single], "");
                    for path in &probes {
                        let got = caps(&combined, path);
                        let lost: Vec<_> = caps(&alone, path).difference(&got).cloned().collect();
                        assert!(lost.is_empty(), "{names:?} on `{path}` loses {lost:?} one of them grants alone");
                    }
                }
            }
        }
    }

    #[test]
    fn full_grants_every_operation_on_the_mount() {
        for (path, name) in [
            ("secret/data/app", "secrets-full"),
            ("resources/resources/db1", "resource-full"),
            ("resources/secrets/db1/root", "resource-full"),
            ("resource-group/groups/prod", "resource-full"),
            ("files/files/f1", "files-full"),
            ("ssh/roles/ops", "ssh-full"),
            ("pki/roles/web", "pki-full"),
            ("pki/root/generate/internal", "pki-full"),
            ("openldap/config", "ad-full"),
            ("totp/keys/k1", "totp-full"),
            ("transit/keys/k1/rotate", "transit-full"),
        ] {
            let got = caps(&acl_of(&[policy(name)], ""), path);
            for c in ["create", "read", "update", "delete", "list"] {
                assert!(got.contains(c), "{name} must grant {c} on {path}, got {got:?}");
            }
        }
    }

    #[test]
    fn read_never_writes_and_never_connects() {
        for (name, hcl) in MODULE_POLICIES.iter().filter(|(n, _)| n.ends_with("-read")) {
            let acl = acl_of(&[hcl], "");
            for path in probes(module_of(name)) {
                if path.starts_with("auth/")
                    || path.starts_with("sys/")
                    || path.starts_with("cubbyhole/")
                    || path.starts_with("rustion/")
                {
                    continue;
                }
                let got = caps(&acl, &path);
                for c in ["create", "update", "delete", "connect", "sudo"] {
                    assert!(!got.contains(c), "{name} grants {c} on {path}");
                }
            }
        }
    }

    /// `-read` reads inventory, never key or credential material.
    #[test]
    fn read_withholds_private_key_and_credential_material() {
        for (name, path) in [
            ("pki-read", "pki/cert/0a:1b/key"),
            ("pki-read", "pki/cert/0a:1b/export"),
            ("pki-read", "pki/issuer/root/export"),
            ("pki-read", "pki/key/k1"),
            ("pki-read", "pki/keys/"),
            ("pki-read", "pki/config/ca"),
            ("ad-read", "openldap/static-cred/svc"),
            ("ad-read", "openldap/config"),
            ("transit-read", "transit/keys/k1/config"),
            ("transit-read", "transit/decrypt/k1"),
            ("totp-read", "totp/code/k1"),
            ("ssh-read", "ssh/sign/ops"),
            ("ssh-read", "ssh/creds/ops"),
        ] {
            assert!(caps(&acl_of(&[policy(name)], ""), path).is_empty(), "{name} must not reach {path}");
        }
    }

    /// `resource-connect` opens a session as the credential without being
    /// able to read it -- the split `may_connect_target` depends on.
    #[test]
    fn resource_connect_conveys_connect_without_read_on_the_credential() {
        let acl = acl_of(&[policy("resource-connect")], "");
        let got = caps(&acl, "resources/secrets/db1/");
        assert!(got.contains("connect"), "got {got:?}");
        assert!(!got.contains("read") && !got.contains("list"), "credential readable: {got:?}");
        let leaf = caps(&acl, "resources/secrets/db1/password");
        assert!(!leaf.contains("read"), "credential readable: {leaf:?}");
        assert!(caps(&acl, "resources/resources/db1").contains("read"), "record must be readable to dial");
        assert!(caps(&acl, "resources/v2/connect/authorize").contains("update"));
        assert!(caps(&acl, "rustion/v2/session/open").contains("update"));
        assert!(!caps(&acl, "rustion/session/open").contains("sudo"), "unbound open needs sudo");
    }

    /// Connect variants use the module, never manage it.
    #[test]
    fn connect_never_manages_the_module() {
        for (name, path) in [
            ("ssh-connect", "ssh/roles/ops"),
            ("ssh-connect", "ssh/config/ca"),
            ("pki-connect", "pki/roles/web"),
            ("pki-connect", "pki/sign-verbatim"),
            ("pki-connect", "pki/revoke"),
            ("ad-connect", "openldap/rotate-role/svc"),
            ("ad-connect", "openldap/static-role/svc"),
            ("totp-connect", "totp/keys/k1"),
            ("transit-connect", "transit/keys/k1/rotate"),
            ("transit-connect", "transit/keys/k1"),
            ("resource-connect", "resources/resources/db1"),
        ] {
            let got = caps(&acl_of(&[policy(name)], ""), path);
            for c in ["create", "update", "delete"] {
                assert!(!got.contains(c), "{name} grants {c} on {path}: {got:?}");
            }
        }
        for (name, path, want) in [
            ("ssh-connect", "ssh/sign/ops", "update"),
            ("ssh-connect", "ssh/creds/ops", "update"),
            ("pki-connect", "pki/issue/web", "update"),
            ("pki-connect", "pki/sign/web", "update"),
            ("ad-connect", "openldap/static-cred/svc", "read"),
            ("ad-connect", "openldap/library/pool/check-out", "update"),
            ("totp-connect", "totp/code/k1", "read"),
            ("transit-connect", "transit/encrypt/k1", "update"),
        ] {
            assert!(caps(&acl_of(&[policy(name)], ""), path).contains(want), "{name} must grant {want} on {path}");
        }
    }

    /// `-shared` grants nothing on any object without a share: every object
    /// rule is share-scoped, which the identity-less dry-run never passes.
    /// (`caps` above probes as LIST, where a scoped rule is a response filter
    /// rather than a gate, so it cannot answer this.)
    #[test]
    fn shared_grants_nothing_without_a_share() {
        use crate::modules::policy::policy::Capability;
        for (name, hcl) in MODULE_POLICIES.iter().filter(|(n, _)| n.ends_with("-shared")) {
            let p = Policy::from_str(hcl).unwrap();
            assert_eq!(
                p.metadata.get("group_shared_resources").map(String::as_str),
                Some("true"),
                "{name} must opt in to group shares"
            );
            let acl = acl_of(&[hcl], "");
            for path in [
                "secret/data/app",
                "secret/metadata/app",
                "resources/resources/db1",
                "resources/secrets/db1/",
                "resource-group/groups/prod",
                "files/files/f1",
            ] {
                for cap in [Capability::Read, Capability::Update, Capability::Connect, Capability::Delete] {
                    assert!(!acl.explain_capability(path, cap).allowed, "{name} grants {cap:?} on {path} with no share");
                }
            }
        }
    }

    /// Rendered for a namespace, a policy reaches that namespace and no other.
    #[test]
    fn rendered_for_a_namespace_it_reaches_only_that_namespace() {
        for (name, hcl) in MODULE_POLICIES.iter().filter(|(n, _)| n.ends_with("-full")) {
            let acl = acl_of(&[hcl], "dti");
            let path = match module_of(name) {
                "secrets" => "secret/data/app",
                "resource" => "resources/resources/db1",
                "files" => "files/files/f1",
                "ssh" => "ssh/roles/ops",
                "pki" => "pki/roles/web",
                "ad" => "openldap/config",
                "totp" => "totp/keys/k1",
                "transit" => "transit/keys/k1",
                other => panic!("no probe for {other}"),
            };
            assert!(caps(&acl, &format!("dti/{path}")).contains("update"), "{name} in dti");
            assert!(caps(&acl, path).is_empty(), "{name} for dti reaches root's {path}");
            assert!(caps(&acl, &format!("outro/{path}")).is_empty(), "{name} reaches another tenant");
        }
    }
}
