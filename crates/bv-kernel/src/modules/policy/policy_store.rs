//! The `policy_store.rs` file manages the storage and retrieval of security policies. It provides
//! mechanisms for setting, getting, listing, and deleting policies. This is crucial in systems
//! that rely on policy-based access controls.
//!
//! The main components include:
//! - PolicyEntry: Represents an individual policy with metadata.
//! - PolicyStore: Manages the lifecycle of policies, including caching and storage.
//!
//! Key functionality includes:
//! - Creation and management of ACL (Access Control List), RGP, and EGP policies.
//! - Policy caching to improve access speed.
//! - Methods to handle CRUD operations on policies.
//!
//! External dependencies:
//! - Uses `stretto` for caching and `dashmap` for concurrent collections.
//!
//! Note:
//! - The code includes placeholder functions (e.g., `handle_sentinel_policy`) intended for future implementation.
//! - The design assumes a highly concurrent environment, where caching is critical.

use std::{
    str::FromStr,
    sync::{Arc, Weak},
};

use better_default::Default;
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use stretto::Cache;

use super::{
    acl::{ACLResults, ACL},
    policy::SentinelPolicy,
    Policy, PolicyType,
};
use crate::kernel_api::VaultCtx;
use crate::{
    core::Core,
    errors::RvError,
    handler::{AuthHandler, Handler},
    logical::{auth::PolicyResults, Operation, Request, Response},
    modules::{
        identity::{GroupKind, IdentityModule, OwnerStore, ShareStore, ShareTargetKind},
        resource_group::{ResourceGroupModule, ResourceGroupStore},
    },
    router::Router,
    bv_error_response_status, bv_error_string,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
};
use serde_json::Value;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// POLICY_ACL_SUB_PATH is the sub-path used for the policy store view. This is
// nested under the system view. POLICY_RGP_SUB_PATH/POLICY_EGP_SUB_PATH are
// similar but for RGPs/EGPs.
const POLICY_ACL_SUB_PATH: &str = "policy/";
const POLICY_RGP_SUB_PATH: &str = "policy-rgp/";
const POLICY_EGP_SUB_PATH: &str = "policy-egp/";
// POLICY_HISTORY_SUB_PATH stores append-only audit entries for ACL policy
// changes. Keys are `{name}/{20-digit-nanos}` so `list` returns entries
// in chronological order. History is retained when the policy is deleted
// so the audit trail remains available after removal.
const POLICY_HISTORY_SUB_PATH: &str = "policy-history/";
// POLICY_TESTS_SUB_PATH stores savable effectivity test cases attached to
// an ACL policy (the graphical builder's regression gate). One key per
// policy name holding a JSON array of `PolicyTestCase`. Kept separate from
// the policy document so a policy's HCL is never polluted with test
// metadata, and a restore of a historical policy version does not clobber
// the present-day test cases. See `features/policy-builder-validator.md`.
const POLICY_TESTS_SUB_PATH: &str = "policy-tests/";

// Multi-tenancy: per-namespace ACL policies and their history live under a
// dedicated keyspace, keyed by the URL-safe base64 of the namespace path so a
// policy named `admin` in one namespace is an entirely separate document from
// `admin` in another. The root namespace ("") is NOT stored here — it keeps the
// legacy `policy/` and `policy-history/` keyspaces, so existing data and the
// root-tenant hot path are untouched. Layout:
//   policy-ns/<b64url(ns_path)>/acl/<name>
//   policy-ns/<b64url(ns_path)>/history/<name>/<seq>
const POLICY_NS_SUB_PATH: &str = "policy-ns/";

/// System-view-relative keyspace holding one namespace's ACL policy documents:
/// `policy/` for the root namespace (`ns_path == ""`), and
/// `policy-ns/<b64url(ns_path)>/acl/` for a tenant.
///
/// Public because subsystems that address the barrier directly rather than
/// through a [`BarrierView`] — the exchange exporter / importer, which walks
/// raw barrier keys — must resolve policies to exactly the keys this store
/// reads and writes. Keep it the single source of truth for the layout.
pub fn acl_keyspace(ns_path: &str) -> String {
    if ns_path.is_empty() {
        return POLICY_ACL_SUB_PATH.to_string();
    }
    let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
    format!("{POLICY_NS_SUB_PATH}{b64}/acl/")
}

/// System-view-relative keyspace holding one namespace's saved policy
/// effectivity test cases, one key per policy name. Companion to
/// [`acl_keyspace`]; see that function for why this is public.
pub fn policy_tests_keyspace(ns_path: &str) -> String {
    if ns_path.is_empty() {
        return POLICY_TESTS_SUB_PATH.to_string();
    }
    let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
    format!("{POLICY_NS_SUB_PATH}{b64}/tests/")
}

// DEFAULT_POLICY_NAME is the name of the default policy
const DEFAULT_POLICY_NAME: &str = "default";
pub static DEFAULT_POLICY: &str = r#"
# Allow tokens to look up their own properties
path "auth/token/lookup-self" {
    capabilities = ["read"]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}

# Allow tokens to record their own GUI sign-in (presenting an existing
# token) to the login-audit trail. The handler only ever records the
# calling token's own identity, so this is safe for every token.
path "auth/token/audit-login" {
    capabilities = ["update"]
}

# Allow a token to look up its own capabilities on a path
path "sys/capabilities-self" {
    capabilities = ["update"]
}

# Allow a token to discover which namespaces it may operate in. The handler
# filters through the caller's own binding + assignment verdict, so it can
# only ever return namespaces the caller already reaches — safe for every
# authenticated token, and the only way a tenant principal (which has no
# grant on the root/sudo-gated `sys/namespaces` CRUD surface) can learn the
# namespace it just logged into.
path "sys/namespaces-self" {
    capabilities = ["read"]
}

# Allow a token to read the GUI Dashboard's operational snapshot. Every count in
# the response (secret engines, auth methods, policies, entities) is built from
# the caller's own ACL and active namespace, so it can only ever report what the
# caller already reaches — the same reasoning that makes `sys/namespaces-self`
# safe for any authenticated token. Without this grant the Dashboard is the
# landing page for every non-root session and its only fetch always 403s.
#
# The deployment-wide audit counters in that response are NOT caller-filtered,
# so `handle_dashboard_summary` omits them unless the caller can read
# `sys/audit/events`. Keep the two in step: widening this grant must not start
# handing global security telemetry to tenant tokens.
path "sys/dashboard/summary" {
    capabilities = ["read"]
}

# Allow a token to look up its own entity by id or name
path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read"]
}
path "identity/entity/name/{{identity.entity.name}}" {
  capabilities = ["read"]
}

# Caller-introspecting self lookup. Resolves the calling token's
# entity_id without needing path templating substitution, which not
# every storage backend supports today. Safe to grant to every
# authenticated token because the handler only ever returns the
# caller's own record.
path "identity/entity/self" {
  capabilities = ["read"]
}

# Self-service profile. Every handler behind these paths resolves the
# principal from the calling token and refuses to touch anyone else's
# record, so they are safe for any authenticated principal:
#   * `profile/self`                  -- read your own account
#   * `profile/self/password`         -- change your own password
#                                        (requires the current one)
#   * `profile/self/contact`          -- your own email / phone
#   * `default-account/self`          -- your own per-OS login names and
#                                        stored Windows RDP password
# The `update` on `default-account/self` is what makes it self-editable;
# the admin `default-account/{mount}/{name}` route is deliberately absent
# here -- that one reaches other people's records and needs a real
# operator policy.
path "sys/identity/profile/self" {
  capabilities = ["read"]
}
path "sys/identity/profile/self/password" {
  capabilities = ["update"]
}
path "sys/identity/profile/self/contact" {
  capabilities = ["update"]
}
path "sys/identity/default-account/self" {
  capabilities = ["read", "update"]
}

# Allow a token to list shares granted to it (direct entity shares plus
# group shares when the assigned policy carries the
# `group_shared_resources = "true"` metadata tag). This is a
# caller-introspecting endpoint -- it only returns the caller's own
# shares -- so it is safe to grant to every authenticated token.
path "identity/sharing/for-me" {
  capabilities = ["read", "list"]
}

# Allow a token to read and manage its own in-app notification inbox
# (list, unread-count, mark-read, mark-all-read, dismiss). The
# notifications backend scopes every inbox operation to the calling
# token's entity_id, so this only ever exposes the caller's own
# notifications. Sending / broadcasting (`notifications/send`), the
# channel + sent + config admin views are deliberately NOT here -- they
# require an admin policy, which is how the ACL enforces who may raise a
# notification.
path "notifications/inbox" {
  capabilities = ["read", "list"]
}
path "notifications/inbox/*" {
  capabilities = ["read", "update", "delete"]
}


# Allow a token to look up its resultant ACL from all policies. This is useful
# for UIs. It is an internal path because the format may change at any time
# based on how the internal ACL features and capabilities change.
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# Allow a token to renew a lease via lease_id in the request body; old path for
# old clients, new path for newer
path "sys/renew" {
    capabilities = ["update"]
}
path "sys/leases/renew" {
    capabilities = ["update"]
}

# Allow looking up lease properties. This requires knowing the lease ID ahead
# of time and does not divulge any sensitive information.
path "sys/leases/lookup" {
    capabilities = ["update"]
}

# Allow a token to manage its own cubbyhole
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow a token to wrap arbitrary values in a response-wrapping token
path "sys/wrapping/wrap" {
    capabilities = ["update"]
}

# Allow a token to look up the creation time and TTL of a given
# response-wrapping token
path "sys/wrapping/lookup" {
    capabilities = ["update"]
}

# Allow a token to unwrap a response-wrapping token. This is a convenience to
# avoid client token swapping since this is also part of the response wrapping
# policy.
path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}

# Allow general purpose tools
path "sys/tools/hash" {
    capabilities = ["update"]
}
path "sys/tools/hash/*" {
    capabilities = ["update"]
}

# Allow checking the status of a Control Group request if the user has the
# accessor
path "sys/control-group/request" {
    capabilities = ["update"]
}

# --- Shared-target access (share-scoped, no ownership) ---------------------
#
# A `default` user can already SEE what's shared with them via
# `identity/sharing/for-me` above; these rules let them actually USE it.
# Every rule is `scopes = ["shared"]` ONLY (deliberately no "owner"), so a
# rule grants access *exclusively* when an active SecretShare exists for the
# (target, caller) pair carrying the capability the operation maps to -- see
# `scope_passes` / `operation_share_capability` in `policy/acl.rs`. With no
# matching share the rule contributes nothing, so this adds no blanket
# resource/secret access and no first-write ownership carve-out: it widens
# the baseline by exactly "you may use what was explicitly shared with you".
# Group-delivered shares still require the opt-in
# `metadata { group_shared_resources = "true" }` tag, intentionally kept out
# of `default` (see the note on `identity/sharing/for-me`).

# KV secrets shared with the caller (read/list; update when the share grants it).
path "secret/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "secret/data/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["shared"]
}

# Resources shared with the caller. `read` = see the resource record (the GUI
# reads it to dial); `update` = the connect path's recent-session stamp;
# `connect` = open a session against its credential. Delete is intentionally
# withheld -- destructive inventory ops need a privileged operator policy,
# matching `standard-user`.
#
# `connect` is listed but never inferred: the scope gate demands `connect` on
# the share itself (`share_capability_override`, see
# `PolicyStore::may_connect_target`), so a share granting only `read` conveys
# no session. That is the whole point of a connect-only grant -- if `read`
# implied it, "may open a session as this credential" and "may see this
# credential" would collapse into one decision.
path "resources/*" {
    capabilities = ["read", "list", "update", "connect"]
    scopes       = ["shared"]
}

# Asset groups shared with the caller. `groups` (list) is ungated like
# `standard-user`; the handler narrows the response set to groups the caller
# owns or has been shared on. `groups/+` (read a specific group) is
# share-scoped.
path "resource-group/groups" {
    capabilities = ["list"]
}
path "resource-group/groups/+" {
    capabilities = ["read"]
    scopes       = ["shared"]
}

# --- Rustion transport visibility (read-only resolvers) --------------------
#
# Not share-scoped, because these are not per-target endpoints: they are pure
# functions over admin-authored transport policy for a resource id the caller
# names. They mint no credential, open no session, and reveal nothing about a
# resource beyond "would a Connect to it route through a bastion, and which
# one". Withheld, the GUI cannot tell that a resource is `rustion-required` --
# and `read_effective_policy` (gui/src-tauri/src/commands/connect.rs) then
# treats the 403 as "no policy", so the transport lock was invisible AND
# unenforced for every share-grantee. The grant is what lets that path fail
# closed instead.
#
# `targets/<id>` read supplies the *pin*: the brokered dial verifies the
# bastion's SSH host-key fingerprint / RDP TLS leaf digest off the target
# record, so without it a share-grantee's bastion hop degrades to unpinned
# TOFU. Target records carry listener coordinates and public-key fingerprints
# -- no secrets. LIST on `targets/` is deliberately withheld, so a caller can
# only resolve bastions the dispatcher already named for them.
#
# The grant is endpoint-level only: both resolvers gate the caller-supplied
# `resource_id` per object (`RustionModuleInner::may_view_resource`), so this
# confers no ability to enumerate the transport tier or fronting bastions of
# resources the caller cannot see. Tier-only resolution (`resource_type` /
# `asset_group_ids` with no `resource_id`) is deliberately ungated -- there is no
# object to authorize against, and the answer is the admin-authored tier chain
# the caller's own sessions already obey.
path "rustion/policy/effective"   { capabilities = ["update"] }
path "rustion/dispatcher/preview" { capabilities = ["update"] }
path "rustion/targets/+"          { capabilities = ["read"] }

# --- Connect-time gates (endpoint-level) -----------------------------------
#
# The pre-flight every Connect runs before a session exists. `mfa/begin` asks
# whether the named profile is gated (the GUI calls it unconditionally --
# `useConnectMfa.gateConnect` -- because the *server* decides, never the
# host); `mfa/verify` proves a factor and mints the single-use ticket;
# `authorize` redeems it on the direct path.
#
# Granted here for the same reason as `rustion/session/open` below: these are
# fixed endpoint paths, not per-object ones, so the ACL check the request
# pipeline runs guards *who may call them*, not *which resource they may name
# in the body*. Each handler re-authorizes the named resource itself through
# `PolicyStore::may_connect_target`, so this reaches no resource the caller
# could not already reach.
#
# Withheld, Connect failed at the first call with a bare 403 for every
# non-root principal -- including callers holding `connect` on the resource
# and `update` on `rustion/v2/session/open`, i.e. everything needed to
# actually open the session they were being refused.
path "resources/v2/connect/mfa/begin"  { capabilities = ["update"] }
path "resources/v2/connect/mfa/verify" { capabilities = ["update"] }
path "resources/v2/connect/authorize"  { capabilities = ["update"] }
"#;

// Implicit self-service policy for namespace-bound tokens.
//
// Multi-tenancy gap: a token whose login namespace is non-root resolves its
// named policies from that namespace's own keyspace (see `get_policy_ns`). A
// freshly-created namespace "starts empty" — it has no `default` policy, and a
// policy written at root is absent from the child keyspace — so a namespace
// token has no grant on the self-service endpoints (`sys/capabilities-self`,
// `auth/token/lookup-self`, token renew/revoke-self, …). Namespace policies
// also cannot re-grant these: `refuse_cross_namespace_paths` rejects `sys/*` /
// `auth/*` rules in a namespace policy because those paths are root-owned. That
// left a namespace principal with no way to introspect its own token.
//
// The fix: every authenticated token bound to a non-root namespace implicitly
// carries this policy in its ACL (injected in `new_acl_inner`). Almost all of it
// is caller-introspecting / self-service — each rule acts solely on the caller's
// own token, identity, capabilities, cubbyhole, or wrapping tokens, so it is safe
// for any authenticated principal regardless of tenant. The one exception is the
// `rustion/` block at the end, which is not caller-scoped by shape: it is scoped
// by the endpoints' own per-resource gates, and carries its rationale inline.
// These paths are `sys/` / `auth/` / `identity/` / `rustion/` (global, never
// namespace-rewritten — see `is_header_scoped_path`), so the bare path rules
// match the un-rewritten request paths exactly. Root tokens are unaffected: this
// is only added when the bound namespace path is non-empty, and root already
// grants the equivalent set via its own `default` policy.
//
// It is never stored, never listed, and never assignable — it exists purely as
// an in-memory ACL contribution, so no per-namespace seeding or backfill of
// existing namespaces is required.
const NAMESPACE_SELF_POLICY_NAME: &str = "namespace-self";
static NAMESPACE_SELF_POLICY: &str = r#"
# --- Token self-service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }

# --- Capability / ACL introspection ---
path "sys/capabilities-self"          { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl"  { capabilities = ["read"] }

# --- Which namespaces this token may operate in (caller-filtered) ---
path "sys/namespaces-self"            { capabilities = ["read"] }

# --- The Dashboard landing page's one aggregation call ---
# Must be granted here as well as in `default`: a namespace-bound token resolves
# its named policies from its own (initially empty) namespace keyspace, so it
# never loads `default` at all — this policy is the entire ACL such a token
# carries. Granting it only in `default` fixes a non-root principal at *root*
# while leaving every tenant session staring at the same 403.
# The counts in the response are resolved through the caller's own ACL and
# namespace, and `handle_dashboard_summary` withholds the deployment-wide audit
# counters from anyone who cannot read `sys/audit/events` — which no tenant token
# can, so this grant exposes nothing beyond what the caller already reaches.
path "sys/dashboard/summary"          { capabilities = ["read"] }

# --- Caller-introspecting identity lookups (only ever return the caller) ---
path "identity/entity/self"   { capabilities = ["read"] }
path "identity/sharing/for-me" { capabilities = ["read", "list"] }

# --- Self-service profile (each handler is scoped to the calling token) ---
path "sys/identity/profile/self"          { capabilities = ["read"] }
path "sys/identity/profile/self/password" { capabilities = ["update"] }
path "sys/identity/profile/self/contact"  { capabilities = ["update"] }
path "sys/identity/default-account/self"  { capabilities = ["read", "update"] }

# --- Own notification inbox (scoped to the caller's entity_id server-side) ---
path "notifications/inbox"   { capabilities = ["read", "list"] }
path "notifications/inbox/*" { capabilities = ["read", "update", "delete"] }

# --- Lease self-service (requires knowing the lease id up front) ---
path "sys/renew"          { capabilities = ["update"] }
path "sys/leases/renew"   { capabilities = ["update"] }
path "sys/leases/lookup"  { capabilities = ["update"] }

# --- Response-wrapping self-service ---
path "sys/wrapping/wrap"   { capabilities = ["update"] }
path "sys/wrapping/lookup" { capabilities = ["update"] }
path "sys/wrapping/unwrap" { capabilities = ["update"] }

# --- Stateless utility ---
path "sys/tools/hash"   { capabilities = ["update"] }
path "sys/tools/hash/*" { capabilities = ["update"] }

# --- Brokered Connect through the deployment-global Rustion fleet ---
# `rustion/` is root-owned and header-scoped -- `is_header_scoped_path` keeps it
# out of the path-rewrite, because the fleet lives only in the root mount table
# and `<ns>/rustion/...` would 404. A namespace policy therefore cannot grant
# these paths at all: `refuse_cross_namespace_paths` rejects any rule naming
# them, since their owner is root and the writer's namespace is not. Granting
# them here is the only route, which is why the block lives in an implicit
# policy rather than in tenant-authored HCL.
#
# Until this landed, a namespace-bound token could not see that a resource was
# `rustion-required`: the resource Connection tab reported the policy as "not
# configured", and the connect path read the 403 from `policy/effective` as "no
# policy visible to me" and dialled *direct* -- resolving the target credential
# onto the operator's machine in defiance of the transport lock. The transport
# tier was invisible, and therefore unenforced, for every tenant.
#
# The two resolvers are read-only pure functions over admin-authored policy for
# a resource id the caller names -- no credential, no session. `targets/<id>`
# read supplies the bastion's transport pin (SSH host-key fingerprint / RDP TLS
# leaf digest) that the brokered dial verifies; without it the tenant's bastion
# hop degrades to unpinned TOFU. Target records carry listener coordinates and
# public-key fingerprints, no secrets. LIST on `targets/` stays withheld, so a
# tenant resolves only the bastions the dispatcher already named.
path "rustion/policy/effective"   { capabilities = ["update"] }
path "rustion/dispatcher/preview" { capabilities = ["update"] }
path "rustion/targets/+"          { capabilities = ["read"] }

# Session lifecycle. Both open endpoints run their OWN per-resource ACL check
# (`RustionModuleInner::may_connect_resource`): the caller must hold `connect` /
# `read` / `root` on `<ns>/resources/secrets/<name>/`, or reach the resource
# through ownership or a share. So these grants reach no resource the caller
# could not already reach -- they only let them reach it *through the bastion*,
# which is the safer of the two routes and the one the policy demands.
# `renew` / `kill` additionally require the `correlation_id` handed only to the
# session's opener.
#
# v1 `session/open` gained that gate so it could be granted here: it is the
# route the client-resolved credential kinds (LDAP / PKI / FIDO2) and every
# brokered RDP session still take, so without it those combinations failed
# closed inside a namespace whenever `rustion-required` was in force. Its
# *unbound* shape -- no `resource_id`, arbitrary target host, caller-supplied
# credential material -- is a fleet-level primitive with no object to authorize
# against, so it requires `sudo` on the path, which this grant does not confer.
path "rustion/session/open"    { capabilities = ["update"] }
path "rustion/v2/session/open" { capabilities = ["update"] }
path "rustion/session/renew"   { capabilities = ["update"] }
path "rustion/session/kill"    { capabilities = ["update"] }

# --- Private per-token workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

// Implicit shared-target policy for namespace-bound tokens.
//
// The mirror of the "Shared-target access" block in `default` (see above), for
// tenants. It exists for the same reason `sys/dashboard/summary` is duplicated
// into `namespace-self`: a namespace-bound token resolves its named policies
// from its own namespace keyspace, and a namespace created by
// `handle_namespace_create` is seeded with mounts but with *no policies at
// all*. Such a token therefore carries only the implicit policies -- which
// granted nothing whatsoever on the namespace's own `secret/`, `resources/`,
// and `resource-group/` mounts. Two consequences, both reported from
// production: `sys/internal/ui/mounts` returned an empty list (the GUI hides
// every mount-gated nav entry, so a tenant with a resource shared with them had
// no Resources tab), and the share itself was unusable.
//
// Every rule is `scopes = ["shared"]` except the `resource-group/groups` list,
// exactly as in `default`: a rule contributes access only when an active
// `SecretShare` exists for the (target, caller) pair carrying the capability
// the operation maps to. With no matching share these rules grant nothing, so
// this widens the tenant baseline by precisely "you may use what was explicitly
// shared with you" -- never blanket access to the namespace's data, and never
// any first-write ownership carve-out (no `owner` scope is granted here).
//
// Paths are `{{namespace.path}}`-templated because, unlike the header-scoped
// `sys/` / `auth/` / `identity/` rules in `namespace-self`, these mounts *are*
// path-rewritten: `rewrite_request_for_namespace` turns a tenant's
// `resources/resources/db1` into `<ns>/resources/resources/db1` before
// authorization. `apply_templates` substitutes the token's bound namespace, so
// the rules can never reach another tenant's path space.
const NAMESPACE_SHARED_POLICY_NAME: &str = "namespace-shared";
static NAMESPACE_SHARED_POLICY: &str = r#"
# KV secrets in this namespace shared with the caller.
path "{{namespace.path}}/secret/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "{{namespace.path}}/secret/data/*" {
    capabilities = ["read", "list", "update"]
    scopes       = ["shared"]
}
path "{{namespace.path}}/secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["shared"]
}

# Resources in this namespace shared with the caller. `read` = see the record,
# `update` = the connect path's recent-session stamp, `connect` = open a
# session. Delete is withheld. As in `default`, `connect` is only ever
# conveyed by a share that carries it explicitly.
path "{{namespace.path}}/resources/*" {
    capabilities = ["read", "list", "update", "connect"]
    scopes       = ["shared"]
}

# Asset groups. `groups` (list) is ungated -- the handler narrows the response
# to groups the caller owns or has been shared on; reading one is share-scoped.
path "{{namespace.path}}/resource-group/groups" {
    capabilities = ["list"]
}
path "{{namespace.path}}/resource-group/groups/+" {
    capabilities = ["read"]
    scopes       = ["shared"]
}

# Connect-time gates, tenant side. The mirror of the block at the end of
# `default`, and the second ungated exception in this policy (the first being
# the `resource-group/groups` list above): the rules are endpoint-level, so
# scoping them to a share would be checking the wrong object -- there is no
# per-target share on `.../connect/mfa/begin`. Each handler re-authorizes the
# resource named in the body via `PolicyStore::may_connect_target`.
#
# Templated, unlike the `rustion/` grants in `namespace-self`: `rustion/` is
# header-scoped and never rewritten (`is_header_scoped_path`), while
# `resources/` IS -- `rewrite_request_for_namespace` turns a tenant's
# `resources/v2/connect/mfa/begin` into `<ns>/resources/v2/connect/mfa/begin`
# before authorization, so a bare rule would silently never match.
path "{{namespace.path}}/resources/v2/connect/mfa/begin"  { capabilities = ["update"] }
path "{{namespace.path}}/resources/v2/connect/mfa/verify" { capabilities = ["update"] }
path "{{namespace.path}}/resources/v2/connect/authorize"  { capabilities = ["update"] }
"#;

// Cross-namespace share access. Assignable, opt-in, share-scoped.
//
// The gap it closes: the implicit `namespace-shared` policy above is injected
// on the strength of the caller's *token binding*, so it reaches a principal
// who logged in to the namespace. It does not reach a principal who logged in
// at root and operates inside the namespace through a cross-namespace
// assignment (`ns_assignment`) — the route the GUI's namespace picker takes.
// Such a caller's request path is rewritten to `<ns>/resources/...` by
// `rewrite_request_for_namespace`, while their ACL is built from `default`,
// whose share-scoped rules are written un-prefixed and therefore match
// nothing. The share was granted, the feed listed it, and every attempt to
// open it 403'd.
//
// Why a named policy rather than widening the implicit injection: injecting
// share access for the request's namespace automatically would silently grant
// it to every principal ever assigned to a namespace, on upgrade, with nothing
// in the policy store to read. Sharing across a tenant boundary is a decision
// an operator should make per principal, so it is spelled out here and
// attached by name.
//
// Every rule is `scopes = ["shared"]` except the `resource-group/groups` list
// and the connect-time endpoint gates, exactly as in `default` and
// `namespace-shared`: a rule contributes access only when an active
// `SecretShare` exists for the (target, caller) pair carrying the capability
// the operation maps to. With no matching share these rules grant nothing, so
// the policy widens the holder's reach by precisely "you may use what was
// explicitly shared with you, in whichever namespace it lives" — never blanket
// access to a namespace's data, and never an ownership carve-out (no `owner`
// scope is granted here).
//
// `{{request.namespace}}` — not `{{namespace.path}}` — is what makes that work
// at any namespace depth: it resolves to the namespace the request is
// addressed to, and to the empty string (with its separator swallowed, see
// `substitute_path`) when the request is addressed to root, so one rule text
// covers `secret/*` and `dti/esi/secret/*` alike. The caller still has to be
// allowed into the namespace at all — `token_operable_resolved` gates that
// independently, and this policy does not confer it.
static SHARED_ACCESS_POLICY_NAME: &str = "shared-access";
static SHARED_ACCESS_POLICY: &str = r#"
# KV secrets shared with the caller, in the namespace being addressed.
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

# Resources shared with the caller. `read` = see the record, `update` = the
# connect path's recent-session stamp, `connect` = open a session against its
# credential. Delete is withheld: destructive inventory operations need a real
# operator policy. `connect` is listed but never inferred — the scope gate
# demands `connect` on the share itself (`share_capability_override`), so a
# share granting only `read` conveys no session.
path "{{request.namespace}}/resources/*" {
    capabilities = ["read", "list", "update", "connect"]
    scopes       = ["shared"]
}

# Asset groups. The `groups` list is ungated -- the handler narrows the
# response to groups the caller owns or has been shared on -- while reading an
# individual group is share-scoped.
path "{{request.namespace}}/resource-group/groups" {
    capabilities = ["list"]
}
path "{{request.namespace}}/resource-group/groups/+" {
    capabilities = ["read"]
    scopes       = ["shared"]
}

# Connect-time gates. Endpoint-level, so scoping them to a share would be
# checking the wrong object -- there is no per-target share on
# `.../connect/mfa/begin`. Each handler re-authorizes the resource named in the
# request body through `PolicyStore::may_connect_target`, so these reach no
# resource the caller could not already reach.
path "{{request.namespace}}/resources/v2/connect/mfa/begin"  { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/mfa/verify" { capabilities = ["update"] }
path "{{request.namespace}}/resources/v2/connect/authorize"  { capabilities = ["update"] }
"#;

// Administrator baseline. Full access to every path with every
// capability — the equivalent of `root` for non-root tokens. Issued
// for break-glass / day-1 admin use; pair with audit logging.
static ADMINISTRATOR_POLICY_NAME: &str = "administrator";
static ADMINISTRATOR_POLICY: &str = r#"
# Full access — every path, every capability.
path "*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
"#;

static RESPONSE_WRAPPING_POLICY_NAME: &str = "response-wrapping";
static RESPONSE_WRAPPING_POLICY: &str = r#"
path "cubbyhole/response" {
    capabilities = ["create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
"#;

static CONTROL_GROUP_POLICY_NAME: &str = "control-group";
static CONTROL_GROUP_POLICY: &str = r#"
path "cubbyhole/control-group" {
    capabilities = ["update", "create", "read"]
}

path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}
"#;

/// Baseline policy for unprivileged users. Seeded on first unseal and
/// editable afterward (not in IMMUTABLE_POLICIES). Grants:
///   - read + list on all KV secrets (so users can read secrets they
///     created or that others granted them visibility to);
///   - create + read + list + update on resources and per-resource
///     secrets (so users can create new resources and populate them);
///   - no delete, no policy/user/mount/identity management;
///   - cubbyhole access + the usual token-self operations from the
///     `default` policy.
///
/// Note: BastionVault does not currently substitute `{{username}}` or
/// similar placeholders in policy paths, so this policy cannot express
/// "only the secrets *you* created". It intentionally grants broad
/// read/list scope across the shared `secret/` and `resources/` mounts;
/// operators who need per-user isolation should either adopt a path
/// convention per user and tighten this policy, or group users via the
/// identity backend so policy assignment is narrower per group.
///
/// Per-user-scoping: read/list capabilities on the shared KV and
/// resource mounts are gated by `scopes = ["owner", "shared"]` so a
/// caller only sees objects they authored or that have been explicitly
/// shared with them (directly, via an identity group when the policy
/// also opts in via `metadata.group_shared_resources = "true"`, or via
/// an asset group whose share targets the caller). The author of an
/// object is stamped on every write through `OwnerStore::record_write`,
/// so newly-created resources remain visible to their creator while
/// the same user does not see other users' objects.
static STANDARD_USER_POLICY_NAME: &str = "standard-user";
static STANDARD_USER_POLICY: &str = r#"
# --- Self service (mirrors the relevant parts of the default policy) ---

path "auth/token/lookup-self" {
    capabilities = ["read"]
}
path "auth/token/renew-self" {
    capabilities = ["update"]
}
path "auth/token/revoke-self" {
    capabilities = ["update"]
}
path "auth/token/audit-login" {
    capabilities = ["update"]
}
path "sys/capabilities-self" {
    capabilities = ["update"]
}
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# Self-service profile: own password (current password required), own
# contact details, own default resource accounts. Caller-scoped
# server-side, so none of it reaches another principal's record.
path "sys/identity/profile/self" {
    capabilities = ["read"]
}
path "sys/identity/profile/self/password" {
    capabilities = ["update"]
}
path "sys/identity/profile/self/contact" {
    capabilities = ["update"]
}
path "sys/identity/default-account/self" {
    capabilities = ["read", "update"]
}

# --- KV secrets (owner/shared-scoped) ---
#
# The `owner` scope carries a first-write carve-out: a Write against
# an unowned target is allowed for any caller with this scope, and
# the write stamps ownership. Subsequent reads/lists/updates only
# resolve through the owner record (the caller authored it) or
# through an active SecretShare. The same pattern applies to
# resources/* below.
path "secret/*" {
    capabilities = ["create", "read", "list", "update"]
    scopes       = ["owner", "shared"]
}
path "secret/data/*" {
    capabilities = ["create", "read", "list", "update"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}

# --- Ownership self-claim ---
# Lets the user stamp themselves as owner of a currently-unowned KV
# path. The handler refuses to overwrite an existing owner.
path "sys/kv-owner/claim" {
    capabilities = ["update"]
}

# --- Resources (owner/shared-scoped) ---
#
# Delete is intentionally not granted -- destructive operations on
# the shared resource inventory should require a privileged operator
# policy.
#
# `connect` reaches an owner unconditionally (the `owner` scope does not
# consult the share) and a grantee only when their share carries it.
path "resources/*" {
    capabilities = ["create", "read", "list", "update", "connect"]
    scopes       = ["owner", "shared"]
}

# --- Asset groups (owner/shared-scoped) ---
#
# List returns every group name (the handler narrows the response set
# to groups the caller owns or has been shared on — see
# `ResourceGroupBackend::handle_list`). Read on a specific group is
# gated by ownership or an active asset-group share, resolved via the
# `scopes = ["shared"]` rule against the share store.
path "resource-group/groups" {
    capabilities = ["list"]
}
path "resource-group/groups/+" {
    capabilities = ["read"]
    scopes       = ["owner", "shared"]
}

# --- Per-user workspace ---

# Each token gets its own private cubbyhole for scratch storage.
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Opt the standard user in to group-share resolution. Without this
# tag, shares whose grantee is an identity group (user or app) are
# silently filtered out — both from the effective ACL and from
# `identity/sharing/for-me`. Operators who want to disable group-share
# visibility for a specific user should attach a custom policy that
# omits this metadata block.
metadata {
    group_shared_resources = "true"
}
"#;

/// Read-only ownership-scoped baseline. Grants a user read+list on any
/// KV secret or resource they *own* (wrote) or that has been explicitly
/// shared with them (once sharing lands). Does not grant create,
/// update, delete, or any administrative capability.
///
/// Complements the existing broadly-scoped `standard-user` policy,
/// which operators can still assign for deployments that have not
/// opted into ownership-aware ACLs.
static STANDARD_USER_READONLY_POLICY_NAME: &str = "standard-user-readonly";
static STANDARD_USER_READONLY_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Self-service profile (each handler is scoped to the calling token) ---
path "sys/identity/profile/self"          { capabilities = ["read"] }
path "sys/identity/profile/self/password" { capabilities = ["update"] }
path "sys/identity/profile/self/contact"  { capabilities = ["update"] }
path "sys/identity/default-account/self"  { capabilities = ["read", "update"] }

# --- KV secrets (owner-scoped read) ---
path "secret/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/data/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}

# --- Resources (owner-scoped read) ---
#
# `connect` belongs here despite the policy's name: read-only describes the
# inventory, not the session. Opening a session authors nothing, and the
# grant still resolves per target -- ownership, or a share that says
# `connect`.
path "resources/*" {
    capabilities = ["read", "list", "connect"]
    scopes       = ["owner", "shared"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

metadata {
    group_shared_resources = "true"
}
"#;

/// Full-CRUD ownership-scoped role. The user manages what they
/// authored — create/read/update/delete/list on any KV secret or
/// resource they own (or have shared with them, once sharing lands).
/// No access to other users' objects without a share. No
/// administrative capabilities.
static SECRET_AUTHOR_POLICY_NAME: &str = "secret-author";
static SECRET_AUTHOR_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Self-service profile (each handler is scoped to the calling token) ---
path "sys/identity/profile/self"          { capabilities = ["read"] }
path "sys/identity/profile/self/password" { capabilities = ["update"] }
path "sys/identity/profile/self/contact"  { capabilities = ["update"] }
path "sys/identity/default-account/self"  { capabilities = ["read", "update"] }

# --- KV secrets (full CRUD on authored/shared items) ---
path "secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list", "delete"]
    scopes       = ["owner", "shared"]
}

# --- Ownership self-claim ---
# Lets the user stamp themselves as owner of a currently-unowned KV
# path. The handler refuses to overwrite an existing owner, so this
# cannot be used to steal authored secrets.
path "sys/kv-owner/claim" {
    capabilities = ["update"]
}

# --- Resources (full CRUD on authored/shared items) ---
path "resources/*" {
    capabilities = ["create", "read", "update", "delete", "list", "connect"]
    scopes       = ["owner", "shared"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Opt the standard user in to group-share resolution. Without this
# tag, shares whose grantee is an identity group (user or app) are
# silently filtered out — both from the effective ACL and from
# `identity/sharing/for-me`. Operators who want to disable group-share
# visibility for a specific user should attach a custom policy that
# omits this metadata block.
metadata {
    group_shared_resources = "true"
}
"#;

/// PKI consumer baseline. Grants a user the right to *use* a PKI mount
/// (issue certificates, sign CSRs, read public CA material and CRLs)
/// without granting any administrative capability over issuers, roles,
/// configuration, or revocation. Pair this with a wildcard mount path
/// (the default `pki/`) or a bespoke mount the operator has stood up
/// for the user's department.
///
/// Operators who run multiple PKI mounts can assign this policy to a
/// group and rely on the inherent path-prefix scoping to limit the
/// blast radius — the policy purposely uses the conventional `pki/`
/// path, so a user with this baseline who does not have access to a
/// `pki-corp/` mount cannot accidentally issue against it.
static PKI_USER_POLICY_NAME: &str = "pki-user";
static PKI_USER_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- PKI: issuance and signing (requires create/update on issue/sign) ---
path "pki/issue/*"          { capabilities = ["create", "update"] }
path "pki/sign/*"           { capabilities = ["create", "update"] }
path "pki/sign-verbatim"    { capabilities = ["create", "update"] }
path "pki/sign-verbatim/*"  { capabilities = ["create", "update"] }

# --- PKI: read public material ---
path "pki/ca"            { capabilities = ["read"] }
path "pki/ca/pem"        { capabilities = ["read"] }
path "pki/ca_chain"      { capabilities = ["read"] }
path "pki/cert/*"        { capabilities = ["read"] }
path "pki/certs"         { capabilities = ["list"] }
path "pki/crl"           { capabilities = ["read"] }
path "pki/crl/pem"       { capabilities = ["read"] }
path "pki/issuers"       { capabilities = ["list", "read"] }
path "pki/issuer/+"      { capabilities = ["read"] }
path "pki/issuer/+/json" { capabilities = ["read"] }
path "pki/issuer/+/pem"  { capabilities = ["read"] }
path "pki/issuer/+/der"  { capabilities = ["read"] }
path "pki/issuer/+/crl"  { capabilities = ["read"] }
path "pki/roles"         { capabilities = ["list"] }
path "pki/roles/*"       { capabilities = ["read"] }

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// PKI administrator baseline. Grants full management of a PKI mount:
/// issuer lifecycle (root generation/import, intermediate signing,
/// rename/delete), role lifecycle, configuration (URLs, CRL settings),
/// tidy/scheduler control, and revocation. Inherits all `pki-user`
/// capabilities. Operators who want to delegate PKI administration to
/// a non-root identity should grant this without granting full `admin`.
static PKI_ADMIN_POLICY_NAME: &str = "pki-admin";
static PKI_ADMIN_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Mount discovery (PKI admin needs to see PKI mounts) ---
path "sys/mounts"   { capabilities = ["read", "list"] }
path "sys/mounts/*" { capabilities = ["read"] }

# --- PKI: full management ---
path "pki/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// TOTP user baseline. Grants the day-to-day operations of a TOTP
/// engine consumer — list keys, fetch a generate-mode code, validate a
/// provider-mode code — while withholding key creation, deletion, and
/// (most importantly) any read of seed metadata that would let the
/// holder enumerate which authenticators are enrolled.
///
/// Path scoping uses the conventional `totp/` mount. Operators who
/// mount at `totp-prod/` or other custom paths grant a per-mount
/// equivalent on top.
static TOTP_USER_POLICY_NAME: &str = "totp-user";
static TOTP_USER_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- TOTP: list which keys exist (names only — metadata is admin) ---
path "totp/keys" { capabilities = ["list"] }

# --- TOTP: generate-mode code fetch + provider-mode validate ---
path "totp/code/*" { capabilities = ["read", "update", "create"] }

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// TOTP administrator baseline. Grants full management of a TOTP
/// mount: create + delete keys, read key metadata, fetch and validate
/// codes. Inherits all `totp-user` capabilities. The seed itself is
/// only ever returned in the create response when `exported = true` —
/// even an admin token cannot re-extract a previously-disclosed seed
/// via these paths, which matches the engine's one-shot-disclosure
/// guarantee.
static TOTP_ADMIN_POLICY_NAME: &str = "totp-admin";
static TOTP_ADMIN_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Mount discovery (TOTP admin needs to see TOTP mounts) ---
path "sys/mounts"   { capabilities = ["read", "list"] }
path "sys/mounts/*" { capabilities = ["read"] }

# --- TOTP: full management ---
path "totp/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// Transit user baseline. Grants the day-to-day operations of a
/// Transit engine consumer — encrypt, decrypt, rewrap, sign, verify,
/// HMAC, datakey, random, hash — while withholding key creation,
/// rotation, configuration, and deletion. Read of key metadata is
/// granted (callers need the public key for asymmetric verify
/// flows); read of secret material via `/export` is **not**.
///
/// Path scoping uses the conventional `transit/` mount.
static TRANSIT_USER_POLICY_NAME: &str = "transit-user";
static TRANSIT_USER_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Transit: list + read public metadata (public keys, version table) ---
path "transit/keys"   { capabilities = ["list"] }
path "transit/keys/*" { capabilities = ["read"] }

# --- Transit: cryptographic operations (no key lifecycle) ---
path "transit/encrypt/*"        { capabilities = ["create", "update"] }
path "transit/decrypt/*"        { capabilities = ["create", "update"] }
path "transit/rewrap/*"         { capabilities = ["create", "update"] }
path "transit/sign/*"           { capabilities = ["create", "update"] }
path "transit/verify/*"         { capabilities = ["create", "update"] }
path "transit/hmac/*"           { capabilities = ["create", "update"] }
path "transit/datakey/*"        { capabilities = ["create", "update"] }
path "transit/random"           { capabilities = ["create", "update"] }
path "transit/random/*"         { capabilities = ["create", "update"] }
path "transit/hash"             { capabilities = ["create", "update"] }
path "transit/hash/*"           { capabilities = ["create", "update"] }

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// Transit administrator baseline. Grants full management of a
/// Transit mount: create + rotate + config + trim + delete keys,
/// plus every operation `transit-user` grants. The engine itself
/// refuses to flip `exportable` to true after creation, so even an
/// admin token cannot retroactively unlock seed export — that
/// stickiness is enforced server-side regardless of policy.
static TRANSIT_ADMIN_POLICY_NAME: &str = "transit-admin";
static TRANSIT_ADMIN_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Mount discovery (Transit admin needs to see Transit mounts) ---
path "sys/mounts"   { capabilities = ["read", "list"] }
path "sys/mounts/*" { capabilities = ["read"] }

# --- Transit: full management ---
path "transit/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// OpenLDAP / AD password-rotation user baseline. Grants the
/// day-to-day operations of an `openldap` engine consumer:
///   * read static credentials (returns the current password),
///   * force a static-role rotation,
///   * check out / check in pool accounts + read pool status,
///   * list configured roles + sets.
///
/// Does NOT grant role / set lifecycle, connection config, or the
/// `rotate-root` endpoint — those are admin-only.
static LDAP_USER_POLICY_NAME: &str = "ldap-user";
static LDAP_USER_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- LDAP: read static credentials + force rotation ---
path "openldap/static-role"      { capabilities = ["list"] }
path "openldap/static-cred/*"    { capabilities = ["read"] }
path "openldap/rotate-role/*"    { capabilities = ["create", "update"] }

# --- LDAP: library check-out / check-in / status ---
path "openldap/library"          { capabilities = ["list"] }
path "openldap/library/*/check-out" { capabilities = ["create", "update"] }
path "openldap/library/*/check-in"  { capabilities = ["create", "update"] }
path "openldap/library/*/status"    { capabilities = ["read"] }

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

/// LDAP administrator baseline. Grants full management of an
/// `openldap` mount: connection config CRUD, role CRUD, library
/// CRUD, `rotate-root`, plus everything `ldap-user` grants.
static LDAP_ADMIN_POLICY_NAME: &str = "ldap-admin";
static LDAP_ADMIN_POLICY: &str = r#"
# --- Self service ---
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "auth/token/audit-login" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }

# --- Mount discovery ---
path "sys/mounts"   { capabilities = ["read", "list"] }
path "sys/mounts/*" { capabilities = ["read"] }

# --- LDAP: full management ---
path "openldap/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# --- Private workspace ---
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
"#;

static _POLICY_STORE_HELP: &str = r#"
TODO
"#;

lazy_static! {
    pub static ref IMMUTABLE_POLICIES: Vec<&'static str> =
        vec!["root", RESPONSE_WRAPPING_POLICY_NAME, CONTROL_GROUP_POLICY_NAME,];
    pub static ref NON_ASSIGNABLE_POLICIES: Vec<&'static str> =
        vec![RESPONSE_WRAPPING_POLICY_NAME, CONTROL_GROUP_POLICY_NAME,];
    /// Parsed, cached instance of the implicit self-service policy granted to
    /// every namespace-bound token. Parsed once at first use; the built-in HCL
    /// is a compile-time constant so a parse failure is a programmer error.
    static ref NAMESPACE_SELF_POLICY_PARSED: Arc<Policy> = {
        let mut p = Policy::from_str(NAMESPACE_SELF_POLICY)
            .expect("built-in namespace self-service policy must parse");
        p.name = NAMESPACE_SELF_POLICY_NAME.to_string();
        p.policy_type = PolicyType::Acl;
        Arc::new(p)
    };
    /// Parsed, cached instance of the implicit shared-target policy granted to
    /// every namespace-bound token. Flagged `templated` so `apply_templates`
    /// resolves `{{namespace.path}}` against the caller's token binding; a
    /// caller with no resolvable binding loses every rule (fail-closed) and the
    /// policy contributes no authorization.
    static ref NAMESPACE_SHARED_POLICY_PARSED: Arc<Policy> = {
        let mut p = Policy::from_str(NAMESPACE_SHARED_POLICY)
            .expect("built-in namespace shared-target policy must parse");
        p.name = NAMESPACE_SHARED_POLICY_NAME.to_string();
        p.policy_type = PolicyType::Acl;
        p.templated = true;
        Arc::new(p)
    };
}

/// Represents a policy entry in the policy store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub version: u32,
    pub raw: String,
    pub templated: bool,
    #[default(PolicyType::Acl)]
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    pub sentinal_policy: SentinelPolicy,
}

/// Audit log entry for a policy change. Records the raw HCL before and
/// after the change so operators can reconstruct prior policy states and
/// roll back by re-submitting `before.raw` if needed. For `create`,
/// `before_raw` is empty; for `delete`, `after_raw` is empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    #[serde(default)]
    pub before_raw: String,
    #[serde(default)]
    pub after_raw: String,
}

/// One savable effectivity test case attached to a policy: an assertion
/// that the policy should `allow` or `deny` `capability` on `path`. These
/// double as documentation of operator intent and as a regression gate on
/// every save. `note` is an optional human description.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyTestCase {
    pub path: String,
    pub capability: String,
    /// "allow" | "deny" — the expected verdict.
    pub expect: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Optional environment fed to the matcher as the `env` request param,
    /// so the rule's env restriction is exercised. Empty = bitmap-only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub env: String,
    /// Optional value assertion: the secret key to compare. Checked live at
    /// Run time by the GUI, not by the save-time regression gate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect_key: String,
    /// Optional value assertion: the expected value of `expect_key`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect_value: String,
}

/// The main policy store structure.
#[derive(Default)]
pub struct PolicyStore {
    pub router: Arc<Router>,
    /// Weak reference back to Core so `post_auth` can resolve optional
    /// subsystems (resource-group) without a strong cycle. Upgrade at
    /// use site; tolerate `None` so unit tests that construct a bare
    /// store continue to work.
    pub core: Weak<Core>,
    pub acl_view: Option<Arc<BarrierView>>,
    pub rgp_view: Option<Arc<BarrierView>>,
    pub egp_view: Option<Arc<BarrierView>>,
    pub history_view: Option<Arc<BarrierView>>,
    /// Barrier sub-view holding savable effectivity test cases, one key
    /// per policy name (root namespace). Non-root namespaces derive their
    /// own keyspace on demand via [`PolicyStore::tests_view_for`].
    pub tests_view: Option<Arc<BarrierView>>,
    /// The system barrier view. Retained so per-namespace ACL/history
    /// sub-views can be derived on demand (see [`PolicyStore::acl_view_for`]).
    /// Multi-tenancy: tenant policies live in their own keyspace under this
    /// view; the root namespace keeps the legacy `acl_view`/`history_view`
    /// keyspaces unchanged for backward compatibility.
    pub system_view: Option<Arc<BarrierView>>,
    pub token_policies_lru: Option<Cache<String, Arc<Policy>>>,
    pub egp_lru: Option<Cache<String, Arc<Policy>>>,
    // Stores whether a token policy is ACL or RGP
    pub policy_type_map: DashMap<String, PolicyType>,
    pub self_ptr: Weak<PolicyStore>,
}

#[maybe_async::maybe_async]
impl PolicyStore {
    /// Creates a new `PolicyStore` with initial setup based on the given `Core`.
    ///
    /// This function initializes views and caches necessary for policy management.
    ///
    /// # Arguments
    ///
    /// * `core` - A reference to the `Core` struct used for initializing views and caches.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<PolicyStore>, RvError>` - An Arc-wrapped `PolicyStore` instance or an error.
    pub async fn new(core: &Core) -> Result<Arc<PolicyStore>, RvError> {
        let Some(system_view) = core.system_view() else {
            return Err(RvError::ErrBarrierSealed);
        };

        let acl_view = system_view.new_sub_view(POLICY_ACL_SUB_PATH);
        let rgp_view = system_view.new_sub_view(POLICY_RGP_SUB_PATH);
        let egp_view = system_view.new_sub_view(POLICY_EGP_SUB_PATH);
        let history_view = system_view.new_sub_view(POLICY_HISTORY_SUB_PATH);
        let tests_view = system_view.new_sub_view(POLICY_TESTS_SUB_PATH);

        let keys = acl_view.get_keys().await?;

        let mut policy_store = PolicyStore {
            router: core.router().clone(),
            core: core.self_ptr.clone(),
            acl_view: Some(Arc::new(acl_view)),
            rgp_view: Some(Arc::new(rgp_view)),
            egp_view: Some(Arc::new(egp_view)),
            history_view: Some(Arc::new(history_view)),
            tests_view: Some(Arc::new(tests_view)),
            system_view: Some(system_view.clone()),
            self_ptr: Weak::default(),
            ..Default::default()
        };

        let policy_cache_size = core.cache_config().policy_cache_size.max(1);
        policy_store.token_policies_lru = Some(
            Cache::builder(policy_cache_size * 10, policy_cache_size as i64)
                .set_ignore_internal_cost(true)
                .finalize()
                .unwrap(),
        );
        policy_store.egp_lru = Some(
            Cache::builder(policy_cache_size * 10, policy_cache_size as i64)
                .set_ignore_internal_cost(true)
                .finalize()
                .unwrap(),
        );

        for key in keys.iter() {
            policy_store.policy_type_map.insert(policy_store.cache_key(key.as_str()), PolicyType::Acl);
        }

        // Special-case root; doesn't exist on disk but does need to be found
        policy_store.policy_type_map.insert(policy_store.cache_key("root"), PolicyType::Acl);

        Ok(policy_store.wrap())
    }

    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    /// Set a policy in the policy store.
    /// This function validates the policy name, checks for immutability, and inserts the policy into the appropriate view.
    pub async fn set_policy(&self, policy: Policy) -> Result<(), RvError> {
        if policy.name.is_empty() {
            return Err(bv_error_string!("policy name missing"));
        }

        let name = self.sanitize_name(&policy.name);
        if IMMUTABLE_POLICIES.contains(&name.as_str()) {
            return Err(bv_error_string!(format!("cannot update {} policy", name)));
        }

        if name != policy.name {
            let mut p = policy.clone();
            p.name = name;
            return self.set_policy_internal(Arc::new(p)).await;
        }

        self.set_policy_internal(Arc::new(policy)).await
    }

    // Get a policy from the policy store.
    // This function retrieves the policy from the appropriate view, checks the cache, and handles policy type mapping.
    pub async fn get_policy(&self, name: &str, policy_type: PolicyType) -> Result<Option<Arc<Policy>>, RvError> {
        let name = self.sanitize_name(name);
        let index = self.cache_key(&name);
        let mut policy_type = policy_type;

        // `policy_type_map` is per-node and in-memory: it is built once in
        // `PolicyStore::new` from the ACL keyspace, and afterwards only by the
        // writes this node itself served. A policy written against another
        // cluster member replicates its bytes through Raft but never reaches
        // this map, so a `Token` lookup could miss for a policy that plainly
        // exists. That miss used to fall through to the `view.is_none()` guard
        // below and fail the whole request with an opaque 500 — including for
        // the much more common case of a token naming a policy that does not
        // exist here at all (typically one created inside a child namespace
        // while the token is root-bound).
        //
        // Resolve the real type from storage instead and memoize it. A name
        // that exists in neither keyspace resolves to `Ok(None)` so
        // `new_acl_inner` skips it and the request is denied on its merits,
        // matching what `get_policy_ns` already does for namespaces.
        if policy_type == PolicyType::Token && name != "root" && !self.policy_type_map.contains_key(&index) {
            if self.get_acl_view()?.get(&name).await?.is_some() {
                self.policy_type_map.insert(index.clone(), PolicyType::Acl);
            } else if self.get_rgp_view()?.get(&name).await?.is_some() {
                self.policy_type_map.insert(index.clone(), PolicyType::Rgp);
            } else {
                // Fail-closed, but say so: silently dropping a policy from a
                // token's ACL is invisible in the 403 that follows, and it is
                // the single hardest symptom to diagnose from the outside.
                log::warn!(
                    "token carries policy '{name}' which does not exist in this namespace; \
                     dropping it from the request ACL"
                );
                return Ok(None);
            }
        }

        let (view, cache) = match policy_type {
            PolicyType::Acl => (Some(self.get_acl_view()?), &self.token_policies_lru),
            PolicyType::Rgp => (Some(self.get_rgp_view()?), &self.token_policies_lru),
            PolicyType::Egp => (Some(self.get_egp_view()?), &self.egp_lru),
            PolicyType::Token => {
                let (v, c) = if let Some(val) = self.policy_type_map.get(&index) {
                    policy_type = *val;
                    match *val {
                        PolicyType::Acl => (Some(self.get_acl_view()?), &self.token_policies_lru),
                        PolicyType::Rgp => (Some(self.get_rgp_view()?), &self.token_policies_lru),
                        _ => {
                            return Err(bv_error_string!(format!(
                                "invalid type of policy in type map: {}",
                                policy_type
                            )))
                        }
                    }
                } else {
                    (None, &None)
                };

                (v, c)
            }
        };

        if let Some(lru) = cache {
            if let Some(p) = lru.get(&index) {
                crate::metrics::cache_metrics::cache_metrics()
                    .record_hit(crate::metrics::cache_metrics::CacheLayer::Policy);
                return Ok(Some(p.value().clone()));
            }
            crate::metrics::cache_metrics::cache_metrics()
                .record_miss(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        if policy_type == PolicyType::Acl && name == "root" {
            let p = Arc::new(Policy { name: "root".into(), ..Default::default() });
            if let Some(lru) = cache {
                lru.insert(index.clone(), p.clone(), 1);
            }
            return Ok(Some(p));
        }

        if view.is_none() {
            // Reachable only for a genuinely unconfigured barrier view now that
            // `Token` resolves through storage above. Name the policy: the old
            // message reported only the type, which told an operator staring at
            // a 500 nothing about which policy to go and look for.
            return Err(bv_error_string!(format!(
                "unable to get the barrier subview for policy '{name}' (type {policy_type})"
            )));
        }

        let view = view.unwrap();

        let entry = view.get(&name).await?;
        if entry.is_none() {
            return Ok(None);
        }

        let entry = entry.unwrap();

        let policy_entry: PolicyEntry = serde_json::from_slice(entry.value.as_slice())?;

        let mut policy = match policy_type {
            PolicyType::Acl => {
                let p = Policy::from_str(&policy_entry.raw)?;
                self.policy_type_map.insert(index.clone(), PolicyType::Acl);
                p
            }
            PolicyType::Rgp => {
                let p = Policy::default();
                self.handle_sentinel_policy(&p, view, &entry)?;
                self.policy_type_map.insert(index.clone(), PolicyType::Rgp);
                p
            }
            PolicyType::Egp => {
                let p = Policy::default();
                self.handle_sentinel_policy(&p, view, &entry)?;
                p
            }
            _ => {
                return Err(bv_error_string!("invalid type of policy"));
            }
        };

        policy.name = name.to_string();
        policy.policy_type = policy_entry.policy_type;
        policy.templated = policy_entry.templated;

        let p = Arc::new(policy);

        if let Some(lru) = cache {
            lru.insert(index.clone(), p.clone(), 1);
        }

        Ok(Some(p))
    }

    /// List policies of a specific type in the policy store.
    /// This function retrieves the keys from the appropriate view and filters out non-assignable policies for ACLs.
    pub async fn list_policy(&self, policy_type: PolicyType) -> Result<Vec<String>, RvError> {
        let view = self.get_barrier_view(policy_type)?;
        match policy_type {
            PolicyType::Acl => {
                let mut keys = view.get_keys().await?;
                keys.retain(|s| !NON_ASSIGNABLE_POLICIES.iter().any(|&x| s == x));
                Ok(keys)
            }
            PolicyType::Rgp | PolicyType::Egp => view.get_keys().await,
            _ => Err(bv_error_string!("invalid type of policy")),
        }
    }

    // -------------------------------------------------------------------
    // Multi-tenancy: namespace-aware policy CRUD.
    //
    // The root namespace ("") delegates to the legacy global methods above so
    // existing behaviour and storage are byte-for-byte unchanged. A non-root
    // namespace stores ACL policies in its own keyspace (see
    // POLICY_NS_SUB_PATH); tenant policies are ACL-only (sentinel RGP/EGP stay
    // root-global). The cache index is namespace-scoped so a name collision
    // across namespaces never poisons another tenant's cached document.
    // -------------------------------------------------------------------

    /// Barrier sub-view holding a namespace's ACL policies. Root returns the
    /// legacy ACL view; a non-root namespace gets a per-namespace keyspace.
    fn acl_view_for(&self, ns_path: &str) -> Result<Arc<BarrierView>, RvError> {
        if ns_path.is_empty() {
            return self.get_acl_view();
        }
        let sv = self
            .system_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("system view unavailable for namespace policy storage"))?;
        Ok(Arc::new(sv.new_sub_view(&acl_keyspace(ns_path))))
    }

    /// Barrier sub-view holding a namespace's ACL policy history.
    fn history_view_for(&self, ns_path: &str) -> Result<Arc<BarrierView>, RvError> {
        if ns_path.is_empty() {
            return self
                .history_view
                .as_ref()
                .cloned()
                .ok_or_else(|| bv_error_string!("policy history view unavailable"));
        }
        let sv = self
            .system_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("system view unavailable for namespace policy storage"))?;
        let b64 = URL_SAFE_NO_PAD.encode(ns_path.as_bytes());
        Ok(Arc::new(sv.new_sub_view(&format!("{POLICY_NS_SUB_PATH}{b64}/history/"))))
    }

    /// Namespace-scoped cache index. Root keeps the bare name (so cached root
    /// documents are unchanged); a non-root namespace prefixes with the path
    /// and a unit-separator that can never appear in a policy name.
    fn ns_cache_key(&self, ns_path: &str, name: &str) -> String {
        if ns_path.is_empty() {
            self.cache_key(name)
        } else {
            format!("ns:{ns_path}\u{1f}{name}")
        }
    }

    /// Get an ACL policy from a specific namespace. Root delegates to the
    /// global [`get_policy`]; a non-root namespace reads from its own keyspace.
    /// The synthetic `root` policy and the request's bound namespace are handled
    /// by the caller; here `name == "root"` always resolves to the global
    /// full-access policy so a namespace-bound root token keeps working.
    pub async fn get_policy_ns(
        &self,
        name: &str,
        policy_type: PolicyType,
        ns_path: &str,
    ) -> Result<Option<Arc<Policy>>, RvError> {
        if ns_path.is_empty() {
            return self.get_policy(name, policy_type).await;
        }
        let name = self.sanitize_name(name);
        // `root` is synthetic everywhere; never stored, never tenant-shadowable.
        if name == "root" {
            return self.get_policy("root", PolicyType::Acl).await;
        }
        let index = self.ns_cache_key(ns_path, &name);
        if let Some(lru) = &self.token_policies_lru {
            if let Some(p) = lru.get(&index) {
                crate::metrics::cache_metrics::cache_metrics()
                    .record_hit(crate::metrics::cache_metrics::CacheLayer::Policy);
                return Ok(Some(p.value().clone()));
            }
            crate::metrics::cache_metrics::cache_metrics()
                .record_miss(crate::metrics::cache_metrics::CacheLayer::Policy);
        }
        let view = self.acl_view_for(ns_path)?;
        let entry = match view.get(&name).await? {
            Some(e) => e,
            None => return Ok(None),
        };
        let policy_entry: PolicyEntry = serde_json::from_slice(entry.value.as_slice())?;
        let mut policy = Policy::from_str(&policy_entry.raw)?;
        policy.name = name;
        policy.policy_type = PolicyType::Acl;
        policy.templated = policy_entry.templated;
        let p = Arc::new(policy);
        if let Some(lru) = &self.token_policies_lru {
            lru.insert(index, p.clone(), 1);
        }
        Ok(Some(p))
    }

    /// Set an ACL policy in a specific namespace. Root delegates to the global
    /// [`set_policy`]; a non-root namespace persists into its own keyspace.
    /// Tenant namespaces only accept ACL policies — sentinel policies remain
    /// root-global and are rejected here.
    pub async fn set_policy_ns(&self, policy: Policy, ns_path: &str) -> Result<(), RvError> {
        if ns_path.is_empty() {
            return self.set_policy(policy).await;
        }
        if policy.name.is_empty() {
            return Err(bv_error_string!("policy name missing"));
        }
        if policy.policy_type != PolicyType::Acl {
            return Err(bv_error_response_status!(
                400,
                "only ACL policies may be created inside a namespace"
            ));
        }
        let name = self.sanitize_name(&policy.name);
        if IMMUTABLE_POLICIES.contains(&name.as_str()) {
            return Err(bv_error_string!(format!("cannot update {} policy", name)));
        }
        let pe = PolicyEntry {
            version: 2,
            templated: policy.templated,
            raw: policy.raw.clone(),
            policy_type: PolicyType::Acl,
            sentinal_policy: policy.sentinal_policy,
        };
        let entry = StorageEntry::new(&name, &pe)?;
        let view = self.acl_view_for(ns_path)?;
        view.put(&entry).await?;
        let index = self.ns_cache_key(ns_path, &name);
        let mut stored = policy;
        stored.name = name;
        self.save_token_policy_cache(index, Arc::new(stored))?;
        Ok(())
    }

    /// List ACL policy names in a specific namespace. Root delegates to the
    /// global [`list_policy`]; a non-root namespace lists only its own keyspace.
    pub async fn list_policy_ns(
        &self,
        policy_type: PolicyType,
        ns_path: &str,
    ) -> Result<Vec<String>, RvError> {
        if ns_path.is_empty() {
            return self.list_policy(policy_type).await;
        }
        let view = self.acl_view_for(ns_path)?;
        let mut keys = view.get_keys().await?;
        keys.retain(|s| !NON_ASSIGNABLE_POLICIES.iter().any(|&x| s == x));
        Ok(keys)
    }

    /// Delete an ACL policy from a specific namespace. Root delegates to the
    /// global [`delete_policy`].
    pub async fn delete_policy_ns(
        &self,
        name: &str,
        policy_type: PolicyType,
        ns_path: &str,
    ) -> Result<(), RvError> {
        if ns_path.is_empty() {
            return self.delete_policy(name, policy_type).await;
        }
        let name = self.sanitize_name(name);
        if IMMUTABLE_POLICIES.contains(&name.as_str()) {
            return Err(bv_error_response_status!(400, format!("cannot delete {} policy", name)));
        }
        if name == "default" {
            return Err(bv_error_response_status!(400, "cannot delete default policy"));
        }
        let view = self.acl_view_for(ns_path)?;
        view.delete(&name).await?;
        self.remove_token_policy_cache(&self.ns_cache_key(ns_path, &name))?;
        Ok(())
    }

    /// Delete a policy from the policy store.
    /// This function removes the policy from the appropriate view, updates the cache, and handles sentinel policy invalidation.
    pub async fn delete_policy(&self, name: &str, policy_type: PolicyType) -> Result<(), RvError> {
        let name = self.sanitize_name(name);
        let view = self.get_barrier_view(policy_type)?;
        let index = self.cache_key(&name);
        match policy_type {
            PolicyType::Acl => {
                if IMMUTABLE_POLICIES.contains(&name.as_str()) {
                    return Err(bv_error_response_status!(400, format!("cannot delete {} policy", name)));
                }
                if name == "default" {
                    return Err(bv_error_response_status!(400, "cannot delete default policy"));
                }
                view.delete(&name).await?;
                self.remove_token_policy_cache(&index)?;
                self.policy_type_map.remove(&index);
            }
            PolicyType::Rgp => {
                view.delete(&name).await?;
                self.remove_token_policy_cache(&index)?;
                self.policy_type_map.remove(&index);
                self.invalidate_sentinal_policy(policy_type, "")?;
            }
            PolicyType::Egp => {
                view.delete(&name).await?;
                self.remove_egp_cache(&index)?;
                self.invalidate_egp_tree_path("")?;
                self.invalidate_sentinal_policy(policy_type, "")?;
            }
            _ => {
                return Err(bv_error_string!("unknown policy type, cannot set"));
            }
        }
        Ok(())
    }

    /// Load an ACL policy into the policy store.
    /// This function retrieves the policy if it exists, validates immutability, and sets the policy.
    pub async fn load_acl_policy(&self, policy_name: &str, policy_text: &str) -> Result<(), RvError> {
        let name = self.sanitize_name(policy_name);
        let policy = self.get_policy(&name, PolicyType::Acl).await?;
        if policy.is_some() && (!IMMUTABLE_POLICIES.contains(&name.as_str()) || policy_text == policy.unwrap().raw) {
            return Ok(());
        }

        let mut policy = Policy::from_str(policy_text)?;
        policy.name.clone_from(&name);
        policy.policy_type = PolicyType::Acl;

        self.set_policy_internal(Arc::new(policy)).await
    }

    /// Force-load an ACL policy, overwriting any existing definition.
    ///
    /// Used for server-managed baselines like `default` whose bundled
    /// text is the source of truth: when the binary ships a new
    /// version, the in-store copy must be updated even if a previous
    /// instance already seeded it. Operators who need to customise
    /// these baselines should attach an additional policy rather than
    /// editing the bundled one in place.
    pub async fn force_load_acl_policy(&self, policy_name: &str, policy_text: &str) -> Result<(), RvError> {
        let name = self.sanitize_name(policy_name);
        let existing = self.get_policy(&name, PolicyType::Acl).await?;
        if matches!(&existing, Some(p) if p.raw == policy_text) {
            return Ok(());
        }
        let mut policy = Policy::from_str(policy_text)?;
        policy.name.clone_from(&name);
        policy.policy_type = PolicyType::Acl;
        self.set_policy_internal(Arc::new(policy)).await
    }

    /// Load default ACL policies into the policy store.
    pub async fn load_default_acl_policy(&self) -> Result<(), RvError> {
        // `default` is server-managed: re-seeded on every startup so
        // upgrades that add new self-service grants take effect on
        // existing vaults without operator intervention.
        self.force_load_acl_policy(DEFAULT_POLICY_NAME, DEFAULT_POLICY).await?;
        self.load_acl_policy(ADMINISTRATOR_POLICY_NAME, ADMINISTRATOR_POLICY).await?;
        self.load_acl_policy(RESPONSE_WRAPPING_POLICY_NAME, RESPONSE_WRAPPING_POLICY).await?;
        self.load_acl_policy(CONTROL_GROUP_POLICY_NAME, CONTROL_GROUP_POLICY).await?;
        // `standard-user` is force-loaded so the per-user-scoping
        // baseline (added in 0.5.22) propagates to existing vaults
        // that were seeded under the older broad-grant version. The
        // change is security-positive — callers can still create
        // new resources/secrets and read what they author or have
        // shared with them, but cross-user listing of unrelated
        // objects is now denied. Operators who deliberately
        // customised this policy should fork it under a new name.
        self.force_load_acl_policy(STANDARD_USER_POLICY_NAME, STANDARD_USER_POLICY).await?;
        // `shared-access` is force-loaded for the same reason as `default`:
        // its text is server-managed, so a vault seeded under an older build
        // picks up later rules without operator intervention. It is inert
        // until an operator attaches it, and inert on any target the holder
        // has no share on.
        self.force_load_acl_policy(SHARED_ACCESS_POLICY_NAME, SHARED_ACCESS_POLICY).await?;
        // Ownership-aware baselines. See `features/per-user-scoping.md`.
        self.load_acl_policy(STANDARD_USER_READONLY_POLICY_NAME, STANDARD_USER_READONLY_POLICY)
            .await?;
        self.load_acl_policy(SECRET_AUTHOR_POLICY_NAME, SECRET_AUTHOR_POLICY).await?;
        // PKI delegated baselines. `pki-user` grants issuance/signing
        // without admin authority; `pki-admin` grants full mount
        // management. See `features/pki-secret-engine.md`.
        self.load_acl_policy(PKI_USER_POLICY_NAME, PKI_USER_POLICY).await?;
        self.load_acl_policy(PKI_ADMIN_POLICY_NAME, PKI_ADMIN_POLICY).await?;
        // TOTP delegated baselines. `totp-user` grants list + code
        // fetch/validate; `totp-admin` grants full mount management.
        // See `features/totp-secret-engine.md`.
        self.load_acl_policy(TOTP_USER_POLICY_NAME, TOTP_USER_POLICY).await?;
        self.load_acl_policy(TOTP_ADMIN_POLICY_NAME, TOTP_ADMIN_POLICY).await?;
        // Transit delegated baselines. `transit-user` grants crypto
        // operations (encrypt / decrypt / sign / verify / hmac /
        // datakey / random / hash) without key lifecycle authority;
        // `transit-admin` grants full mount management.
        // See `features/transit-secret-engine.md`.
        self.load_acl_policy(TRANSIT_USER_POLICY_NAME, TRANSIT_USER_POLICY).await?;
        self.load_acl_policy(TRANSIT_ADMIN_POLICY_NAME, TRANSIT_ADMIN_POLICY).await?;
        // OpenLDAP / AD delegated baselines.
        self.load_acl_policy(LDAP_USER_POLICY_NAME, LDAP_USER_POLICY).await?;
        self.load_acl_policy(LDAP_ADMIN_POLICY_NAME, LDAP_ADMIN_POLICY).await?;
        Ok(())
    }

    /// Create a new ACL instance from a list of policy names and additional policies.
    /// This function retrieves policies by name, combines them with additional policies, and creates an ACL.
    pub async fn new_acl(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
    ) -> Result<ACL, RvError> {
        self.new_acl_inner(policy_names, additional_policies, None, None).await
    }

    /// ACL construction with templating context. Templated policies (those
    /// detected at parse time to contain `{{...}}` placeholders in their
    /// path strings) are deep-cloned and substituted using the caller's
    /// identity (`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`).
    /// Substitution rules mirror `features/per-user-scoping.md` §1:
    /// placeholders that cannot be resolved cause the owning path rule
    /// to be dropped (fail-closed) with a logged warning. Non-templated
    /// policies pass through untouched.
    /// `request_ns` is the namespace the request being authorized is
    /// addressed to (`req.namespace_path`), which is **not** the namespace the
    /// token is bound to: a root-bound principal holding a cross-namespace
    /// assignment operates inside a tenant while its binding stays root. It
    /// feeds the `{{request.namespace}}` template, so pass it whenever a real
    /// request is in hand; `None` fail-closes every rule that uses that
    /// placeholder.
    pub async fn new_acl_for_request(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
        auth: &crate::logical::Auth,
        request_ns: Option<&str>,
    ) -> Result<ACL, RvError> {
        self.new_acl_inner(policy_names, additional_policies, Some(auth), request_ns)
            .await
    }

    /// Which of `target_paths` may this caller actually *read*? Returns a
    /// parallel `Vec<bool>`.
    ///
    /// An endpoint that returns a *set* of objects cannot be secured by the
    /// pre-route check alone: `post_auth` authorizes the endpoint path (say
    /// `resources/search`), not the individual objects in its response. This
    /// re-runs the real evaluator once per candidate against a synthesized
    /// per-object request carrying the same three qualifier inputs `post_auth`
    /// resolves for a direct read — asset-group membership, owner entity, and
    /// shared capabilities — so a `groups = [...]` or
    /// `scopes = ["owner", "shared"]` rule decides exactly as it would had the
    /// caller read the object itself. Root short-circuits inside
    /// `allow_operation`, so a root token keeps its unfiltered view.
    ///
    /// Fails closed: an unbuildable ACL, a missing `auth`, or an evaluator
    /// error marks the target not-readable.
    ///
    /// Prefer this over `ACL::explain_capability` for response filtering.
    /// `explain_capability` deliberately probes with an identity-less dry-run
    /// request so that scope-gated rules contribute nothing — right for
    /// "does an explicit ungated grant exist?", wrong here: it would hide
    /// every object whose access comes from ownership or a share, which is
    /// precisely the access a filtered list exists to reveal.
    ///
    /// Cost is one ACL build plus, per candidate, up to three store lookups.
    /// Callers filtering a large candidate set should narrow it first.
    pub async fn readable_targets(
        &self,
        req: &Request,
        target_paths: &[String],
    ) -> Vec<bool> {
        let mut out = vec![false; target_paths.len()];
        let Some(auth) = req.auth.as_ref() else {
            return out;
        };
        if auth.policies.is_empty() {
            return out;
        }
        let ns = req.namespace_path.as_deref();
        let Ok(acl) = self.new_acl_for_request(&auth.policies, None, auth, ns).await else {
            return out;
        };
        for (i, target) in target_paths.iter().enumerate() {
            let mut probe = Request::new(target);
            probe.operation = Operation::Read;
            probe.auth = req.auth.clone();
            probe.namespace_path = req.namespace_path.clone();
            probe.api_version = req.api_version;

            // First pass with the qualifiers left empty. A `groups` /
            // `scopes` qualifier can only ever *gate* a rule — never grant
            // beyond it — so an allow here (an ungated grant, or root) is
            // already conclusive, and the three lookups below are skipped.
            // That keeps the admin path at one ACL build and no extra reads.
            let ungated = acl
                .allow_operation(&probe, false)
                .map(|r| r.allowed || r.root_privs)
                .unwrap_or(false);
            if ungated {
                out[i] = true;
                continue;
            }

            probe.asset_groups = resolve_asset_groups(&self.core, target, ns).await;
            probe.asset_owner = resolve_asset_owner(&self.core, target, ns).await;
            probe.target_shared_caps = resolve_target_shared_caps(&self.core, &probe).await;
            out[i] = match acl.allow_operation(&probe, false) {
                Ok(r) => r.allowed || r.root_privs,
                Err(_) => false,
            };
        }
        out
    }

    /// May this caller open a session against `secret_prefix`
    /// (`<ns>/resources/secrets/<name>/`)?
    ///
    /// The single authority for "may connect", shared by every connect gate
    /// — `rustion/v2/session/open`'s `may_connect_resource`, the resource
    /// mount's `require_connect_grant`, and the direct-path
    /// `resources/v2/connect/authorize`. It lives here rather than in either
    /// module because it was duplicated once and the copies drifted: the
    /// resource-mount copy claimed to be an "identical probe" while missing
    /// the share/owner-aware arm, so every share-grantee was refused at
    /// `connect/mfa/begin` while `session/open` let them through.
    ///
    /// Three arms, in cost order:
    ///
    /// 1. An ungated `connect` grant in admin-authored policy.
    /// 2. An ungated `read` grant. A caller who may read the credential can
    ///    already open the session by hand, so withholding `connect` from
    ///    them would be theatre.
    /// 3. Ownership, or a share that carries `connect` **explicitly**.
    ///
    /// Arms 1–2 use the identity-less dry-run, so scope-gated rules
    /// contribute nothing there — they are answered by arm 3, which
    /// populates the same qualifier inputs `post_auth` resolves for a real
    /// request. `read` does *not* imply connect on that arm: a share is
    /// user-authored delegation, and letting "see this secret" silently mean
    /// "open sessions as it" would hand out the one capability a
    /// connect-only grant exists to isolate. A grantor who wants both grants
    /// both.
    ///
    /// Fails closed on a missing `auth` or an unbuildable ACL.
    pub async fn may_connect_target(&self, req: &Request, secret_prefix: &str) -> bool {
        use crate::modules::policy::policy::Capability;

        let Some(auth) = req.auth.as_ref() else {
            return false;
        };
        if auth.policies.is_empty() {
            return false;
        }
        let Ok(acl) = self
            .new_acl_for_request(&auth.policies, None, auth, req.namespace_path.as_deref())
            .await
        else {
            return false;
        };

        let connect = acl.explain_capability(secret_prefix, Capability::Connect);
        if connect.allowed || connect.is_root {
            return true;
        }
        if acl.explain_capability(secret_prefix, Capability::Read).allowed {
            return true;
        }

        let ns = req.namespace_path.as_deref();
        let mut probe = Request::new(secret_prefix);
        probe.operation = Operation::Read;
        probe.auth = req.auth.clone();
        probe.namespace_path = req.namespace_path.clone();
        probe.api_version = req.api_version;
        probe.asset_groups = resolve_asset_groups(&self.core, secret_prefix, ns).await;
        probe.asset_owner = resolve_asset_owner(&self.core, secret_prefix, ns).await;
        probe.target_shared_caps = resolve_target_shared_caps(&self.core, &probe).await;
        // Read op, `connect` capability: the probe rides on Read because
        // that is how every non-LIST capability is matched, while the
        // override makes a `scopes = ["shared"]` rule demand `connect` on
        // the share rather than the `read` the operation would imply.
        probe.share_capability_override = Some("connect".to_string());

        let verdict = acl.explain_capability_for_request(&probe, Capability::Connect);
        verdict.allowed || verdict.is_root
    }

    async fn new_acl_inner(
        &self,
        policy_names: &[String],
        additional_policies: Option<Vec<Arc<Policy>>>,
        auth: Option<&crate::logical::Auth>,
        request_ns: Option<&str>,
    ) -> Result<ACL, RvError> {
        // Multi-tenancy: load each named policy from the namespace the calling
        // token is bound to. Root-bound tokens (and every non-auth caller)
        // resolve `ns_path == ""`, which delegates to the global keyspace and
        // preserves the pre-namespace hot path exactly.
        let ns_path = auth
            .map(|a| crate::modules::namespace::token_binding::binding_from_metadata(&a.metadata).0)
            .unwrap_or_default();
        let mut all_policies: Vec<Arc<Policy>> = vec![];
        for policy_name in policy_names.iter() {
            if let Some(policy) = self
                .get_policy_ns(policy_name.as_str(), PolicyType::Token, &ns_path)
                .await?
            {
                all_policies.push(policy);
            }
        }

        // Multi-tenancy: a namespace-bound token's named policies resolve from
        // its (initially empty) namespace keyspace, so it would otherwise carry
        // no grant on the self-service endpoints — it could not even look itself
        // up or query its own capabilities. Inject the implicit self-service
        // policy for any non-root binding. Root tokens (`ns_path == ""`) are
        // untouched; they get the same endpoints from their real `default`
        // policy, so the pre-namespace hot path is byte-for-byte unchanged.
        if !ns_path.is_empty() {
            all_policies.push(NAMESPACE_SELF_POLICY_PARSED.clone());
            // Same rationale, for the namespace's own data mounts: without this
            // a tenant token has no grant on `<ns>/resources/*` et al, so a
            // resource shared with them is both invisible (empty
            // `sys/internal/ui/mounts` -> no Resources tab) and unreachable.
            // Share-scoped only -- see NAMESPACE_SHARED_POLICY.
            all_policies.push(NAMESPACE_SHARED_POLICY_PARSED.clone());
        }

        if let Some(ap) = additional_policies {
            all_policies.extend(ap);
        }

        // Apply templating substitution to any policy flagged `templated`
        // when we have a caller context. Produces a parallel Vec of
        // Arc<Policy> that ACL::new consumes.
        let materialized: Vec<Arc<Policy>> = all_policies
            .into_iter()
            .filter_map(|p| {
                if p.templated {
                    match auth {
                        Some(a) => apply_templates(&p, a, request_ns),
                        // No caller context: drop templated policies
                        // fail-closed rather than let literal `{{...}}`
                        // strings reach path matching where they would
                        // never hit a real request.
                        None => {
                            log::warn!(
                                "dropping templated policy '{}' because no caller \
                                 context is available for substitution",
                                p.name,
                            );
                            None
                        }
                    }
                } else {
                    Some(p)
                }
            })
            .collect();

        ACL::new(&materialized)
    }

    async fn set_policy_internal(&self, policy: Arc<Policy>) -> Result<(), RvError> {
        let view = self.get_barrier_view(policy.policy_type)?;
        let pe = PolicyEntry {
            version: 2,
            templated: policy.templated,
            raw: policy.raw.clone(),
            policy_type: policy.policy_type,
            sentinal_policy: policy.sentinal_policy,
        };

        let entry = StorageEntry::new(&policy.name, &pe)?;

        let index = self.cache_key(&policy.name);

        match policy.policy_type {
            PolicyType::Acl => {
                let rgp_view = self.get_rgp_view()?;
                let rgp = rgp_view.get(&policy.name).await?;
                if rgp.is_some() {
                    return Err(bv_error_string!("cannot reuse policy names between ACLs and RGPs"));
                }

                view.put(&entry).await?;

                self.policy_type_map.insert(index.clone(), PolicyType::Acl);

                self.save_token_policy_cache(index.clone(), policy.clone())?;
            }
            PolicyType::Rgp => {
                let acl_view = self.get_acl_view()?;
                let acl = acl_view.get(&policy.name).await?;
                if acl.is_some() {
                    return Err(bv_error_string!("cannot reuse policy names between ACLs and RGPs"));
                }

                self.handle_sentinel_policy(policy.as_ref(), view, &entry)?;

                self.policy_type_map.insert(index.clone(), PolicyType::Rgp);

                self.save_token_policy_cache(index.clone(), policy.clone())?;
            }
            PolicyType::Egp => {
                self.handle_sentinel_policy(policy.as_ref(), view, &entry)?;
                self.save_egp_cache(index.clone(), policy.clone())?;
            }
            _ => {
                return Err(bv_error_string!("unknown policy type, cannot set"));
            }
        }

        Ok(())
    }

    fn get_barrier_view(&self, _policy_type: PolicyType) -> Result<Arc<BarrierView>, RvError> {
        self.get_acl_view()
    }

    fn get_acl_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.acl_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type acl")),
        }
    }

    fn get_rgp_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.rgp_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type rpg")),
        }
    }

    fn get_egp_view(&self) -> Result<Arc<BarrierView>, RvError> {
        match &self.egp_view {
            Some(view) => Ok(view.clone()),
            None => Err(bv_error_string!("unable to get the barrier subview for policy type epg")),
        }
    }

    fn save_token_policy_cache(&self, index: String, policy: Arc<Policy>) -> Result<(), RvError> {
        if let Some(lru) = &self.token_policies_lru {
            if !lru.insert(index, policy, 1) {
                return Err(bv_error_string!("save token policy cache failed!"));
            }
        }

        Ok(())
    }

    /// Flush every cached policy and zeroize the held Arcs. Called by
    /// `Core::flush_caches` on seal and by the `sys/cache/flush` admin
    /// endpoint. Safe to call when the cache is already empty.
    pub fn flush_caches(&self) {
        if let Some(lru) = &self.token_policies_lru {
            lru.clear().ok();
        }
        if let Some(lru) = &self.egp_lru {
            lru.clear().ok();
        }
    }

    fn remove_token_policy_cache(&self, index: &String) -> Result<(), RvError> {
        if let Some(lru) = &self.token_policies_lru {
            lru.remove(index);
            crate::metrics::cache_metrics::cache_metrics()
                .record_eviction(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        Ok(())
    }

    fn save_egp_cache(&self, index: String, policy: Arc<Policy>) -> Result<(), RvError> {
        if let Some(lru) = &self.egp_lru {
            if !lru.insert(index, policy, 1) {
                return Err(bv_error_string!("save token policy cache failed!"));
            }
        }

        Ok(())
    }

    fn remove_egp_cache(&self, index: &String) -> Result<(), RvError> {
        if let Some(lru) = &self.egp_lru {
            lru.remove(index);
            crate::metrics::cache_metrics::cache_metrics()
                .record_eviction(crate::metrics::cache_metrics::CacheLayer::Policy);
        }

        Ok(())
    }

    fn handle_sentinel_policy(
        &self,
        _policy: &Policy,
        _view: Arc<BarrierView>,
        _entry: &StorageEntry,
    ) -> Result<(), RvError> {
        Ok(())
    }

    fn invalidate_sentinal_policy(&self, _policy_type: PolicyType, _index: &str) -> Result<(), RvError> {
        Ok(())
    }

    fn invalidate_egp_tree_path(&self, _index: &str) -> Result<(), RvError> {
        Ok(())
    }

    /// Sanitize a policy name by converting it to lowercase.
    fn sanitize_name(&self, name: &str) -> String {
        name.to_lowercase().to_string()
    }

    /// Generate a cache key for a given policy name.
    fn cache_key(&self, name: &str) -> String {
        name.to_string()
    }

    /// Append an audit entry for a policy change. The entry is keyed by
    /// `{name}/{20-digit-nanos}` so history for a single policy can be
    /// listed in chronological order by sorting.
    pub async fn append_history(
        &self,
        name: &str,
        entry: PolicyHistoryEntry,
    ) -> Result<(), RvError> {
        let view = self
            .history_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("policy history view unavailable"))?;
        let name = self.sanitize_name(name);
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Return the full history for a single policy, newest entry first.
    /// History persists after the policy is deleted so audit records
    /// remain available until explicitly purged.
    pub async fn list_history(
        &self,
        name: &str,
    ) -> Result<Vec<PolicyHistoryEntry>, RvError> {
        let view = self
            .history_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("policy history view unavailable"))?;
        let name = self.sanitize_name(name);
        let prefix = format!("{name}/");
        let mut keys = view.list(&prefix).await?;
        keys.sort();
        keys.reverse();

        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<PolicyHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }

    /// Namespace-scoped variant of [`append_history`]. Root delegates to the
    /// global history keyspace; a non-root namespace keeps its own audit trail.
    pub async fn append_history_ns(
        &self,
        name: &str,
        entry: PolicyHistoryEntry,
        ns_path: &str,
    ) -> Result<(), RvError> {
        if ns_path.is_empty() {
            return self.append_history(name, entry).await;
        }
        let view = self.history_view_for(ns_path)?;
        let name = self.sanitize_name(name);
        let key = format!("{name}/{}", hist_seq());
        let value = serde_json::to_vec(&entry)?;
        view.put(&StorageEntry { key, value }).await
    }

    /// Namespace-scoped variant of [`list_history`].
    pub async fn list_history_ns(
        &self,
        name: &str,
        ns_path: &str,
    ) -> Result<Vec<PolicyHistoryEntry>, RvError> {
        if ns_path.is_empty() {
            return self.list_history(name).await;
        }
        let view = self.history_view_for(ns_path)?;
        let name = self.sanitize_name(name);
        let prefix = format!("{name}/");
        let mut keys = view.list(&prefix).await?;
        keys.sort();
        keys.reverse();
        let mut entries = Vec::with_capacity(keys.len());
        for k in keys {
            let full = format!("{prefix}{k}");
            if let Some(e) = view.get(&full).await? {
                if let Ok(h) = serde_json::from_slice::<PolicyHistoryEntry>(&e.value) {
                    entries.push(h);
                }
            }
        }
        Ok(entries)
    }

    /// Barrier sub-view holding a namespace's policy test cases. Root
    /// returns the legacy tests view; a non-root namespace gets its own
    /// keyspace, mirroring [`PolicyStore::history_view_for`].
    fn tests_view_for(&self, ns_path: &str) -> Result<Arc<BarrierView>, RvError> {
        if ns_path.is_empty() {
            return self
                .tests_view
                .as_ref()
                .cloned()
                .ok_or_else(|| bv_error_string!("policy tests view unavailable"));
        }
        let sv = self
            .system_view
            .as_ref()
            .ok_or_else(|| bv_error_string!("system view unavailable for namespace policy storage"))?;
        Ok(Arc::new(sv.new_sub_view(&policy_tests_keyspace(ns_path))))
    }

    /// Return the saved effectivity test cases for a policy (empty when
    /// none have been saved). Namespace-scoped; root passes `""`.
    pub async fn get_policy_tests_ns(
        &self,
        name: &str,
        ns_path: &str,
    ) -> Result<Vec<PolicyTestCase>, RvError> {
        let view = self.tests_view_for(ns_path)?;
        let name = self.sanitize_name(name);
        match view.get(&name).await? {
            Some(e) => Ok(serde_json::from_slice::<Vec<PolicyTestCase>>(&e.value).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Overwrite the saved effectivity test cases for a policy. An empty
    /// list deletes the stored entry so a policy with no cases leaves no
    /// residue. Namespace-scoped; root passes `""`.
    pub async fn set_policy_tests_ns(
        &self,
        name: &str,
        cases: &[PolicyTestCase],
        ns_path: &str,
    ) -> Result<(), RvError> {
        let view = self.tests_view_for(ns_path)?;
        let name = self.sanitize_name(name);
        if cases.is_empty() {
            view.delete(&name).await?;
            return Ok(());
        }
        let value = serde_json::to_vec(cases)?;
        view.put(&StorageEntry { key: name, value }).await
    }
}

/// Strip the active namespace prefix from a request path, yielding the
/// mount-relative form (`resources/resources/db1`) that the shape helpers
/// below match against.
///
/// `rewrite_request_for_namespace` prepends `<ns>/` to every non-header-scoped
/// request, so inside a namespace the ACL sees `dti/esi/resources/resources/db1`.
/// Without this strip none of the extractors matched, every owner / share /
/// asset-group lookup resolved to "nothing", and `scopes = ["owner"|"shared"]`
/// rules were silently ungrantable for resources, files, and asset groups
/// inside a namespace. The failure was closed, but it made sharing unusable for
/// tenants. Paths that do not carry the prefix (root requests, or a path the
/// rewriter left alone) pass through unchanged.
fn mount_relative_path<'a>(req_path: &'a str, ns_path: Option<&str>) -> &'a str {
    let p = req_path.strip_prefix('/').unwrap_or(req_path);
    let Some(ns) = ns_path.map(|n| n.trim().trim_matches('/')).filter(|n| !n.is_empty()) else {
        return p;
    };
    p.strip_prefix(ns).and_then(|r| r.strip_prefix('/')).unwrap_or(p)
}

/// Extract a resource name from `request_path` if it targets the
/// resource engine, namespace-scoped for owner/share lookup.
///
/// The resource module is mounted at `resources/` and its internal paths
/// include `resources/<name>` (metadata) and `secrets/<resource>/<key>`
/// (per-resource secrets). The full request path (pre-mount-strip) therefore
/// looks like `resources/resources/<name>` or `resources/secrets/<resource>/<key>`,
/// with a `<ns>/` prefix inside a namespace. Returns `None` for any other path
/// shape, which is the signal to treat `asset_groups` as empty.
///
/// The returned value is the *storage key*, not the display name: bare at root,
/// `<ns>/<name>` in a namespace (see `OwnerStore::scope_target_name`).
fn resource_name_from_path(req_path: &str, ns_path: Option<&str>) -> Option<String> {
    let p = mount_relative_path(req_path, ns_path);
    let rest = p.strip_prefix("resources/")?;
    let rest = rest.strip_prefix("resources/").or_else(|| rest.strip_prefix("secrets/"))?;
    let name = rest.split('/').next()?;
    OwnerStore::scope_target_name(name, ns_path)
}

/// Extract a file id from `request_path` if it targets the files
/// engine, namespace-scoped for owner/share lookup.
///
/// The files module is mounted at `files/` and its metadata
/// path is `files/<id>` (plus optional sub-segments like `/content` or
/// `/history`). The full request path is therefore
/// `files/files/<id>[/...]`. Returns the id on match (ownership hooks
/// only fire on the metadata endpoint; `/content` and `/history`
/// should not restamp ownership).
fn file_id_from_path(req_path: &str, ns_path: Option<&str>) -> Option<String> {
    let p = mount_relative_path(req_path, ns_path);
    let rest = p.strip_prefix("files/")?;
    let rest = rest.strip_prefix("files/")?;
    let mut parts = rest.splitn(2, '/');
    let id = parts.next()?;
    OwnerStore::scope_target_name(id, ns_path)
}

/// As `file_id_from_path`, but only returns the id when the remainder
/// of the path is empty — i.e. the request targets the file metadata
/// directly and not a sub-endpoint like `/content` or `/history`.
fn file_id_from_metadata_path(req_path: &str, ns_path: Option<&str>) -> Option<String> {
    let p = mount_relative_path(req_path, ns_path);
    let rest = p.strip_prefix("files/")?;
    let rest = rest.strip_prefix("files/")?;
    // No further `/` segment means this is the metadata leaf path.
    if rest.contains('/') {
        return None;
    }
    OwnerStore::scope_target_name(rest, ns_path)
}

/// Extract an asset-group name from a `resource-group/groups/<name>`
/// path, namespace-scoped for owner/share lookup. Returns `None` for the list
/// path itself, the history sub-path, or any non-matching shape. Names are
/// lowercased to match `ResourceGroupStore::sanitize_name` so the lookup key
/// matches what the store persists.
fn asset_group_name_from_path(req_path: &str, ns_path: Option<&str>) -> Option<String> {
    let p = mount_relative_path(req_path, ns_path);
    let rest = p.strip_prefix("resource-group/groups/")?;
    // Reject the trailing slash list form and the per-group sub-paths
    // (`<name>/history`); only the bare leaf matches.
    if rest.contains('/') {
        return None;
    }
    OwnerStore::scope_target_name(rest, ns_path)
}

/// Does `request_path` look like a KV (v1 or v2) request? The routing
/// layer puts KV mounts under their operator-chosen path (default
/// `secret/`). We can't enumerate mounts from here cheaply, so we use
/// a permissive heuristic: anything that is *not* one of the fixed
/// non-KV prefixes (`sys/`, `auth/`, `identity/`, `resource-group/`,
/// `cubbyhole/`, `resources/`) is treated as a candidate KV path. If
/// the secret-index has no entry for it, `groups_for_secret` returns
/// an empty vec and the evaluator moves on. Worst case: a request for
/// a non-KV path outside this allowlist hits one extra index lookup.
///
/// Takes `ns_path` so a namespaced request is tested mount-relative: without
/// it `dti/esi/resources/resources/db1` matches none of the non-KV prefixes and
/// a tenant's resource request is misclassified as a KV path.
fn looks_like_kv_path(req_path: &str, ns_path: Option<&str>) -> bool {
    let p = mount_relative_path(req_path, ns_path);
    const NON_KV_PREFIXES: &[&str] = &[
        "sys/",
        "auth/",
        "identity/",
        "resource-group/",
        "cubbyhole/",
        "resources/",
        "files/",
    ];
    !p.is_empty() && !NON_KV_PREFIXES.iter().any(|pref| p.starts_with(pref))
}

/// Best-effort resolve of the owner entity_id for the request target.
/// Returns an empty string on any failure (module absent, no owner
/// record, path shape we don't recognize). `scope_passes` treats an
/// empty `asset_owner` as "no owner match", so a resolution miss can
/// only narrow access for owner-scoped rules.
async fn resolve_asset_owner(core: &Weak<Core>, req_path: &str, ns_path: Option<&str>) -> String {
    let Some(core) = core.upgrade() else {
        return String::new();
    };
    let Some(module) = core.module_manager().get_module::<IdentityModule>("identity") else {
        return String::new();
    };
    let Some(store) = module.owner_store() else {
        return String::new();
    };
    if let Some(name) = resource_name_from_path(req_path, ns_path) {
        if let Ok(Some(rec)) = store.get_resource_owner(&name).await {
            return rec.entity_id;
        }
    }
    if let Some(id) = file_id_from_path(req_path, ns_path) {
        if let Ok(Some(rec)) = store.get_file_owner(&id).await {
            return rec.entity_id;
        }
    }
    if looks_like_kv_path(req_path, ns_path) {
        // Key on the namespace-scoped canonical path so a child-namespace
        // secret's owner (stamped under `<ns>/<mount>/<key>` by
        // `post_route`) is found here. Falls back to the raw path for root.
        let key = OwnerStore::canonicalize_kv_path_scoped(req_path, ns_path)
            .unwrap_or_else(|| req_path.to_string());
        if let Ok(Some(rec)) = store.get_kv_owner(&key).await {
            return rec.entity_id;
        }
    }
    // Asset group: the owner is captured on first write to
    // `resource-group/groups/<name>` and lives on the group entry
    // (not the identity OwnerStore). Pull from the resource-group
    // store directly.
    // The group record itself is still keyed on the bare name in a global
    // store, so a namespaced lookup (`<ns>/<group>`) simply misses and the
    // owner scope fails closed — the same outcome as before this path became
    // namespace-aware, and deliberately not a silent fall back to root's group
    // of the same name. Namespacing `ResourceGroupStore` is the follow-up.
    if let Some(name) = asset_group_name_from_path(req_path, ns_path) {
        if let Some(rg_module) = core
            .module_manager()
            .get_module::<ResourceGroupModule>("resource-group")
        {
            if let Some(rg_store) = rg_module.store() {
                if let Ok(Some(g)) = rg_store.get_group(&name).await {
                    return g.owner_entity_id;
                }
            }
        }
    }
    String::new()
}

/// Best-effort lookup of the capabilities the caller has on the
/// request target via any non-expired `SecretShare`. Returns an
/// empty vec on any failure (module absent, store not yet
/// initialized, caller has no `entity_id`, path shape we don't
/// recognize). A resolution miss can only narrow access for
/// shared-scoped rules — fail-closed.
async fn resolve_target_shared_caps(
    core: &Weak<Core>,
    req: &Request,
) -> Vec<String> {
    let Some(caller_id) = req
        .auth
        .as_ref()
        .and_then(|a| a.metadata.get("entity_id"))
        .cloned()
    else {
        return Vec::new();
    };
    if caller_id.is_empty() {
        return Vec::new();
    }
    let Some(core) = core.upgrade() else {
        return Vec::new();
    };
    let Some(module) = core.module_manager().get_module::<IdentityModule>("identity") else {
        return Vec::new();
    };
    let Some(store) = module.share_store() else {
        return Vec::new();
    };

    // Direct shares first (kind = resource or kv-secret), then
    // indirect shares via asset-group membership — a share granted
    // on a group name covers every current member of the group.
    // Capabilities from all matching shares union together.
    let mut caps: Vec<String> = Vec::new();
    let mut merge = |more: Vec<String>| {
        for c in more {
            if !caps.iter().any(|x| x == &c) {
                caps.push(c);
            }
        }
    };

    let ns = req.namespace_path.as_deref();
    if let Some(name) = resource_name_from_path(&req.path, ns) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::Resource, &name, &caller_id)
            .await
        {
            merge(v);
        }
    }
    if looks_like_kv_path(&req.path, ns) {
        // Shares are keyed on the namespace-scoped canonical path (see
        // `create_share`), so scope the request path the same way before
        // looking up the caller's shared capabilities.
        let key = OwnerStore::canonicalize_kv_path_scoped(&req.path, req.namespace_path.as_deref())
            .unwrap_or_else(|| req.path.clone());
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::KvSecret, &key, &caller_id)
            .await
        {
            merge(v);
        }
    }
    if let Some(id) = file_id_from_path(&req.path, ns) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::File, &id, &caller_id)
            .await
        {
            merge(v);
        }
    }
    // Direct: the request targets an asset-group path itself
    // (`resource-group/groups/<name>`). Look up any asset-group share
    // addressed to the caller entity for this group.
    if let Some(name) = asset_group_name_from_path(&req.path, ns) {
        if let Ok(v) = store
            .shared_capabilities(ShareTargetKind::AssetGroup, &name, &caller_id)
            .await
        {
            merge(v);
        }
    }

    // Indirect: walk the caller's asset-group memberships for this
    // target and union any asset-group shares addressed to them. We
    // already have the list on `req.asset_groups` — `post_auth`
    // populated it before this helper runs, so no extra lookup is
    // needed against the reverse index. Silent on any failure.
    if !req.asset_groups.is_empty() {
        for group in &req.asset_groups {
            if let Ok(v) = store
                .shared_capabilities(ShareTargetKind::AssetGroup, group, &caller_id)
                .await
            {
                merge(v);
            }
        }
    }

    // Identity-group grantees: when one of the caller's attached
    // policies opts in via `metadata.group_shared_resources = "true"`,
    // also resolve shares whose grantee is an identity group (user or
    // app) the caller belongs to. Without this expansion, group-
    // grantee shares show up in the "Shared with me" feed (which has
    // its own group walk) but the underlying read/list ACL still 403s
    // because the share is not keyed on the caller's entity_id.
    let group_shared = caller_policies_opt_in_group_shared(&core, req).await;
    if group_shared {
        let username = req
            .auth
            .as_ref()
            .and_then(|a| a.metadata.get("username"))
            .cloned()
            .unwrap_or_default();
        let role_name = req
            .auth
            .as_ref()
            .and_then(|a| a.metadata.get("role_name"))
            .cloned()
            .unwrap_or_default();

        if let Some(gs) = module.group_store() {
            for (kind, member) in [
                (GroupKind::User, &username),
                (GroupKind::App, &role_name),
            ] {
                if member.is_empty() {
                    continue;
                }
                let m_lc = member.trim().to_lowercase();
                let Ok(names) = gs.list_groups(kind).await else {
                    continue;
                };
                for g_name in names {
                    let Ok(Some(g)) = gs.get_group(kind, &g_name).await else {
                        continue;
                    };
                    let is_member =
                        g.members.iter().any(|m| m.trim().to_lowercase() == m_lc);
                    if !is_member {
                        continue;
                    }

                    // Direct shares granted to this group on the target.
                    if let Some(name) = resource_name_from_path(&req.path, ns) {
                        if let Ok(v) = store
                            .shared_capabilities(ShareTargetKind::Resource, &name, &g_name)
                            .await
                        {
                            merge(v);
                        }
                    }
                    if looks_like_kv_path(&req.path, ns) {
                        // Canonicalize exactly as the entity-grantee lookup
                        // above does: shares are stored under the scoped
                        // canonical path, so passing the raw request path here
                        // missed every KV group-share in a namespace (and every
                        // v2 `data/`-infixed one at root).
                        let key = OwnerStore::canonicalize_kv_path_scoped(&req.path, ns)
                            .unwrap_or_else(|| req.path.clone());
                        if let Ok(v) = store
                            .shared_capabilities(
                                ShareTargetKind::KvSecret,
                                &key,
                                &g_name,
                            )
                            .await
                        {
                            merge(v);
                        }
                    }
                    if let Some(id) = file_id_from_path(&req.path, ns) {
                        if let Ok(v) = store
                            .shared_capabilities(ShareTargetKind::File, &id, &g_name)
                            .await
                        {
                            merge(v);
                        }
                    }

                    // Asset-group shares granted to this group, where
                    // the target is a member of the asset group.
                    for ag in &req.asset_groups {
                        if let Ok(v) = store
                            .shared_capabilities(
                                ShareTargetKind::AssetGroup,
                                ag,
                                &g_name,
                            )
                            .await
                        {
                            merge(v);
                        }
                    }

                    // Asset-group share where the request path itself
                    // is `resource-group/groups/<name>` and the share
                    // grantee is this identity group. Lets a member
                    // of grp-teste read the do-tic-esi group metadata
                    // when the share grants it.
                    if let Some(ag_name) = asset_group_name_from_path(&req.path, ns) {
                        if let Ok(v) = store
                            .shared_capabilities(
                                ShareTargetKind::AssetGroup,
                                &ag_name,
                                &g_name,
                            )
                            .await
                        {
                            merge(v);
                        }
                    }
                }
            }
        }
    }

    caps
}

/// True when any of the caller's effective policies carries the
/// `metadata.group_shared_resources = "true"` opt-in tag. Mirrors the
/// check in `IdentityModule::handle_share_for_me_list` so visibility
/// (the "Shared with me" feed) and enforcement (the `scopes=["shared"]`
/// ACL check) agree on whether identity-group shares apply to this
/// caller. Silent on any policy-store failure (returns `false`,
/// fail-closed — the absence of group-share resolution just narrows
/// access rather than widening it).
async fn caller_policies_opt_in_group_shared(core: &crate::core::Core, req: &Request) -> bool {
    let Some(auth) = req.auth.as_ref() else {
        return false;
    };
    if auth.policies.is_empty() {
        return false;
    }
    let Some(pmodule) = core
        .module_manager()
        .get_module::<crate::modules::policy::PolicyModule>("policy")
    else {
        return false;
    };
    let pstore = pmodule.policy_store.load();
    for name in &auth.policies {
        if let Ok(Some(p)) = pstore
            .get_policy(name, crate::modules::policy::policy::PolicyType::Acl)
            .await
        {
            if p.metadata
                .get("group_shared_resources")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

/// Best-effort lookup of the asset-groups that contain the request
/// target. Consults the resource-index when the path looks like a
/// resource engine path, then (independently) the secret-index when
/// the path looks like a KV path. The two lookups can both contribute
/// — a group-gated policy rule can reference a group whose members
/// include both resources and secrets, and either kind of target
/// passing the gate is enough for the rule to apply.
///
/// Returns an empty vec on any failure (module absent, store not yet
/// initialized, path we don't recognize, storage error). The ACL
/// evaluator treats empty here as "target is in no groups", so a
/// lookup failure can only narrow access, never widen it.
async fn resolve_asset_groups(
    core: &Weak<Core>,
    req_path: &str,
    ns_path: Option<&str>,
) -> Vec<String> {
    let Some(core) = core.upgrade() else {
        return Vec::new();
    };
    let Some(module) = core.module_manager().get_module::<ResourceGroupModule>("resource-group") else {
        return Vec::new();
    };
    let Some(store) = module.store() else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();

    if let Some(name) = resource_name_from_path(req_path, ns_path) {
        if let Ok(groups) = store.groups_for_resource(&name).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    if looks_like_kv_path(req_path, ns_path) {
        if let Ok(groups) = store.groups_for_secret(req_path).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    if let Some(id) = file_id_from_path(req_path, ns_path) {
        if let Ok(groups) = store.groups_for_file(&id).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }

    out
}

/// Substitute `{{username}}`, `{{entity.id}}`, and `{{auth.mount}}`
/// in every path of a templated policy using the caller's `Auth`.
///
/// Returns a cloned `Arc<Policy>` with substituted paths on success,
/// or `None` when every path rule dropped (unresolved placeholders).
/// Path rules whose substitution fails are dropped individually; the
/// rest of the policy is retained. Warnings are logged.
///
/// Substitution vocabulary (v1):
///   `{{username}}`   — `auth.metadata["username"]`, falling back to
///                      `auth.display_name`.
///   `{{entity.id}}`  — `auth.metadata["entity_id"]`.
///   `{{auth.mount}}` — `auth.metadata["mount_path"]` (populated by
///                      the auth backend when available).
///   `{{namespace.path}}` — the token's bound namespace path (root = "",
///                      a legitimate value).
///   `{{namespace.id}}`   — the token's bound namespace UUID (fail-closed
///                      when absent, e.g. root/login tokens).
///   `{{request.namespace}}` — the namespace this *request* is addressed to
///                      (root = "", a legitimate value). Fail-closed when
///                      `request_ns` is `None`, i.e. outside the request
///                      pipeline. See `substitute_path`.
fn apply_templates(
    policy: &Arc<Policy>,
    auth: &crate::logical::Auth,
    request_ns: Option<&str>,
) -> Option<Arc<Policy>> {
    let username = auth
        .metadata
        .get("username")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| auth.display_name.clone());
    let entity_id = auth
        .metadata
        .get("entity_id")
        .cloned()
        .unwrap_or_default();
    let auth_mount = auth
        .metadata
        .get("mount_path")
        .cloned()
        .unwrap_or_default();
    // Multi-tenancy templates: the namespace the request's token is bound to.
    // `namespace.path` defaults to the root namespace (empty string), which is
    // a legitimate value; `namespace.id` is opaque and fail-closed when absent.
    let namespace_path = auth
        .metadata
        .get(crate::modules::namespace::token_binding::NS_PATH_META)
        .cloned()
        .unwrap_or_default();
    let namespace_id = auth
        .metadata
        .get(crate::modules::namespace::token_binding::NS_ID_META)
        .cloned()
        .unwrap_or_default();

    let mut cloned: Policy = Policy::clone(policy);
    let mut kept: Vec<crate::modules::policy::PolicyPathRules> =
        Vec::with_capacity(cloned.paths.len());
    let mut dropped = 0usize;

    for mut rule in cloned.paths.drain(..) {
        match substitute_path(
            &rule.path,
            &username,
            &entity_id,
            &auth_mount,
            &namespace_path,
            &namespace_id,
            request_ns,
        ) {
            Some(new_path) => {
                rule.path = new_path;
                kept.push(rule);
            }
            None => {
                log::warn!(
                    "policy '{}': dropping path rule '{}' — unresolved template placeholder",
                    cloned.name,
                    rule.path,
                );
                dropped += 1;
            }
        }
    }

    if kept.is_empty() {
        log::warn!(
            "policy '{}': all {} path rule(s) dropped due to unresolved template placeholders; \
             policy contributes no authorization this turn",
            cloned.name,
            dropped,
        );
        return None;
    }

    cloned.paths = kept;
    Some(Arc::new(cloned))
}

/// Replace every supported `{{...}}` placeholder with its value.
/// Returns `None` if any `{{...}}` placeholder cannot be resolved
/// (e.g., `{{username}}` on a root-token request where auth metadata
/// is empty). An unknown placeholder name (outside the v1 vocabulary)
/// is also treated as unresolved, so typos are fail-closed.
fn substitute_path(
    path: &str,
    username: &str,
    entity_id: &str,
    auth_mount: &str,
    namespace_path: &str,
    namespace_id: &str,
    request_namespace: Option<&str>,
) -> Option<String> {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}")?;
        let key = after[..end].trim();
        let value = match key {
            // BastionVault-native vocabulary.
            "username" | "identity.entity.name" => {
                if username.is_empty() {
                    return None;
                }
                username
            }
            "entity.id" | "identity.entity.id" => {
                if entity_id.is_empty() {
                    return None;
                }
                entity_id
            }
            "auth.mount" | "identity.entity.mount" => {
                if auth_mount.is_empty() {
                    return None;
                }
                auth_mount
            }
            // Multi-tenancy: the root namespace's path is legitimately empty,
            // so `namespace.path` is allowed to substitute the empty string.
            "namespace.path" => namespace_path,
            // The namespace the *request* is addressed to, which is not the
            // same thing as the namespace the token is bound to: a root-bound
            // principal carrying a cross-namespace assignment (see
            // `ns_assignment`) operates inside a tenant while its binding
            // stays root. Fail-closed without a request context — an ACL built
            // outside the request pipeline (`new_acl`) cannot know which
            // namespace a rule would be addressing, and guessing root there
            // would silently point a tenant-scoped rule at the root mounts.
            "request.namespace" => request_namespace?,
            // The namespace id is opaque; an absent id is unresolved (root and
            // login tokens carry no id today), so fail closed like other ids.
            "namespace.id" => {
                if namespace_id.is_empty() {
                    return None;
                }
                namespace_id
            }
            _ => return None,
        };
        // `{{request.namespace}}` resolves to "" at root, so a rule written as
        // `{{request.namespace}}/resources/*` would otherwise become
        // `/resources/*` — a path that matches nothing, because request paths
        // carry no leading slash. Swallow the separator that the placeholder
        // was meant to introduce so the same rule text addresses the root
        // mounts and a tenant's mounts alike. Deliberately not applied to
        // `namespace.path`: that placeholder's empty-at-root behaviour is
        // load-bearing for policies already in the field, and quietly turning
        // their inert `/secret/*` rules into live `secret/*` ones would widen
        // access on upgrade.
        let consume_separator = key == "request.namespace" && value.is_empty();
        out.push_str(value);
        rest = &after[end + 2..];
        if consume_separator {
            rest = rest.strip_prefix('/').unwrap_or(rest);
        }
    }
    out.push_str(rest);
    Some(out)
}

/// Monotonic-ish 20-digit zero-padded nanoseconds since UNIX epoch, used
/// as the suffix of history log keys so listing returns entries in
/// chronological order. Mirrors the resource/identity modules.
fn hist_seq() -> String {
    let n = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() * 1_000_000);
    format!("{:020}", n.max(0) as u128)
}

#[maybe_async::maybe_async]
impl AuthHandler for PolicyStore {
    fn name(&self) -> String {
        "policy_store".to_string()
    }

    /// Handle authentication for a given request.
    /// This function checks the request path, performs capability checks, and updates authentication results.
    async fn post_auth(&self, req: &mut Request) -> Result<(), RvError> {
        let is_root_path = self.router.is_root_path(&req.path)?;

        if req.auth.is_none() && is_root_path {
            return Err(bv_error_string!("cannot access root path in unauthenticated request"));
        }

        let mut acl_result = ACLResults::default();

        if let Some(auth) = &req.auth {
            if auth.policies.is_empty() {
                return Ok(());
            }

            // Resolve the request target's resource-group membership once so
            // the (sync) ACL evaluator can enforce the `groups = [...]`
            // policy qualifier against it. Cheap lookup — one read against
            // the reverse member-index view. Absence of the subsystem, or a
            // non-resource path, leaves `asset_groups` empty (= the path
            // matches no groups, and any `groups`-gated rule is skipped).
            req.asset_groups =
                resolve_asset_groups(&self.core, &req.path, req.namespace_path.as_deref()).await;
            // Resolve the request target's owner entity_id for the
            // `scopes = ["owner"]` check. Same shape as asset_groups:
            // empty on any failure, which is fail-closed for
            // owner-scoped rules.
            req.asset_owner =
                resolve_asset_owner(&self.core, &req.path, req.namespace_path.as_deref()).await;
            // Resolve any active `SecretShare` capabilities the caller
            // has on this target so `scopes = ["shared"]` rules can be
            // evaluated synchronously downstream. Empty when the
            // caller has no entity_id, no share exists, or the share
            // has expired.
            req.target_shared_caps = resolve_target_shared_caps(&self.core, req).await;

            let acl = self
                .new_acl_for_request(&auth.policies, None, auth, req.namespace_path.as_deref())
                .await?;
            acl_result = acl.allow_operation(req, false)?;
        }

        // Stash the list-filter groups + scopes on the request so the
        // post-route pass can filter the response keys. See the
        // `Handler::post_route` impl below.
        req.list_filter_groups = acl_result.list_filter_groups.clone();
        req.list_filter_scopes = acl_result.list_filter_scopes.clone();

        if let Some(auth) = &mut req.auth {
            if is_root_path && !acl_result.root_privs && req.operation != Operation::Help {
                return Err(bv_error_string!("cannot access root path in unauthenticated request"));
            }

            let allowed = acl_result.allowed;

            auth.policy_results = Some(PolicyResults { allowed, granting_policies: acl_result.granting_policies });

            if !allowed {
                log::warn!(
                    "preflight capability check returned 403, please ensure client's policies grant access to path \
                     \"{}\"",
                    req.path
                );
                return Err(RvError::ErrPermissionDenied);
            }
        }

        Ok(())
    }
}

#[maybe_async::maybe_async]
impl Handler for PolicyStore {
    fn name(&self) -> String {
        "policy_store".to_string()
    }

    /// Post-route pass. Covers two asset-group integration concerns:
    ///
    /// 1. **List-filter.** If `req.list_filter_groups` is non-empty
    ///    (set by `post_auth` when the list was authorized only by a
    ///    `groups = [...]`-gated rule), restrict the response keys to
    ///    those whose resolved full path is a member of any listed
    ///    group. Respects both the resource-index (for `resources/`
    ///    paths) and the secret-index (for KV paths).
    ///
    /// 2. **KV-delete prune.** On a successful `Delete` of a KV path,
    ///    call `ResourceGroupStore::prune_secret` so the deleted
    ///    secret disappears from every asset group it was a member
    ///    of. Parallels the resource-delete hook in the resource
    ///    module. Failures are logged but never fail the delete —
    ///    `resource-group/reindex` is the recovery path.
    async fn post_route(
        &self,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        let rg_store = self.resource_group_store();
        let owner_store = self.owner_store();
        // Active namespace, and the mount-relative view of the request path.
        // Every owner / share / asset-group key below is namespace-scoped, and
        // the `starts_with` shape guards only hold on the un-prefixed path.
        let ns = req.namespace_path.as_deref();
        let rel = mount_relative_path(&req.path, ns).to_string();

        // --- Asset-group list filter ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::List && !req.list_filter_groups.is_empty() {
                if let Some(response) = resp.as_mut() {
                    filter_list_response(response, &req.path, &req.list_filter_groups, store, ns)
                        .await;
                }
            }
        }

        // --- Ownership list filter ---
        // Narrows LIST response keys to entries the caller owns (and,
        // once sharing lands, entries shared with them). Operates
        // independently of the asset-group filter; a LIST granted by
        // both a `scopes=["owner"]` rule and a `groups=[...]` rule
        // applies both filters in sequence, which is the intended
        // intersection — each filter narrows further.
        if let Some(store) = owner_store.as_ref() {
            if req.operation == Operation::List && !req.list_filter_scopes.is_empty() {
                if let Some(response) = resp.as_mut() {
                    let caller_id = req
                        .auth
                        .as_ref()
                        .and_then(|a| a.metadata.get("entity_id"))
                        .cloned()
                        .unwrap_or_default();
                    let share_store = self.share_store();
                    filter_list_by_ownership(
                        response,
                        &req.path,
                        &req.list_filter_scopes,
                        &caller_id,
                        store,
                        share_store.as_ref(),
                        req.namespace_path.as_deref(),
                    )
                    .await;
                }
            }
        }

        // --- Owner bookkeeping ---
        if let Some(store) = owner_store.as_ref() {
            // `caller_id` is the caller's `entity_id` when present,
            // otherwise `display_name` (so root-token writes stamp
            // `"root"` rather than orphan the record). This matches the
            // audit-actor fallback and keeps the Owner card on the GUI
            // useful for admin-created resources — an earlier version of
            // this hook skipped ownership capture whenever `entity_id`
            // was empty, which left every root-created resource
            // permanently "Unowned".
            //
            // ACL impact is zero: root bypasses policy, and for other
            // callers the comparison in `scope_passes` is entity_id vs
            // entity_id — a literal "root" owner cannot accidentally
            // grant owner-scope access because no other caller has
            // `entity_id = "root"` in their auth metadata.
            //
            // `audit_actor` (already defined below for share-cascade
            // revoke audit rows) computes the same value, so reuse it.
            let audit_actor = crate::modules::identity::caller_audit_actor(req);
            let caller_id = audit_actor.clone();

            match req.operation {
                Operation::Write => {
                    if looks_like_kv_path(&req.path, ns) && !caller_id.is_empty() {
                        // Stamp under the namespace-scoped canonical key so a
                        // child-namespace secret's owner is stored where the
                        // owner-read, share, and ACL paths look for it.
                        let key = OwnerStore::canonicalize_kv_path_scoped(
                            &req.path,
                            req.namespace_path.as_deref(),
                        )
                        .unwrap_or_else(|| req.path.clone());
                        let _ = store.record_kv_owner_if_absent(&key, &caller_id).await;
                    }
                    if let Some(name) = resource_name_from_path(&req.path, ns) {
                        // Only stamp ownership on the metadata create
                        // path (`resources/resources/<name>`), not on
                        // per-resource secret writes under
                        // `resources/secrets/<name>/...`.
                        if rel.starts_with("resources/resources/") && !caller_id.is_empty() {
                            let _ = store
                                .record_resource_owner_if_absent(&name, &caller_id)
                                .await;
                        }
                    }
                    // File resources: stamp owner on the metadata
                    // path (`files/files/<id>`, i.e. a replace-by-id
                    // write). For the create path (`files/files`
                    // without id), the file engine stamps the owner
                    // inline — post_route cannot because the new id is
                    // only visible to the module that assigned it.
                    if let Some(id) = file_id_from_metadata_path(&req.path, ns) {
                        if !caller_id.is_empty() {
                            let _ = store
                                .record_file_owner_if_absent(&id, &caller_id)
                                .await;
                        }
                    }
                }
                Operation::Delete => {
                    if looks_like_kv_path(&req.path, ns) {
                        let key = OwnerStore::canonicalize_kv_path_scoped(&req.path, ns)
                            .unwrap_or_else(|| req.path.clone());
                        let _ = store.forget_kv_owner(&key).await;
                    }
                    if let Some(name) = resource_name_from_path(&req.path, ns) {
                        if rel.starts_with("resources/resources/") {
                            let _ = store.forget_resource_owner(&name).await;
                        }
                    }
                    if let Some(id) = file_id_from_metadata_path(&req.path, ns) {
                        let _ = store.forget_file_owner(&id).await;
                    }
                    // Cascade-delete every SecretShare referencing this
                    // target so dangling share rows do not outlive the
                    // secret/resource. Failures are logged but never
                    // fail the delete — stale share records deny
                    // access anyway once `get_share` returns None.
                    //
                    // The audited variant stamps the caller's entity_id
                    // on each emitted cascade-revoke event so the
                    // Admin → Audit page attributes the action to the
                    // user that triggered the target delete.
                    if let Some(sshare) = self.share_store() {
                        if looks_like_kv_path(&req.path, ns) {
                            // Shares are keyed on the namespace-scoped canonical
                            // path; scope before cascading so a child-namespace
                            // secret's shares are actually found and revoked.
                            let key = OwnerStore::canonicalize_kv_path_scoped(&req.path, ns)
                                .unwrap_or_else(|| req.path.clone());
                            if let Err(e) = sshare
                                .cascade_delete_target_audited(
                                    ShareTargetKind::KvSecret,
                                    &key,
                                    &audit_actor,
                                )
                                .await
                            {
                                log::warn!(
                                    "share cascade-delete failed for KV path '{}': {e}",
                                    req.path,
                                );
                            }
                        }
                        if let Some(name) = resource_name_from_path(&req.path, ns) {
                            if rel.starts_with("resources/resources/") {
                                if let Err(e) = sshare
                                    .cascade_delete_target_audited(
                                        ShareTargetKind::Resource,
                                        &name,
                                        &audit_actor,
                                    )
                                    .await
                                {
                                    log::warn!(
                                        "share cascade-delete failed for resource '{}': {e}",
                                        name,
                                    );
                                }
                            }
                        }
                        if let Some(id) = file_id_from_metadata_path(&req.path, ns) {
                            if let Err(e) = sshare
                                .cascade_delete_target_audited(
                                    ShareTargetKind::File,
                                    &id,
                                    &audit_actor,
                                )
                                .await
                            {
                                log::warn!(
                                    "share cascade-delete failed for file '{}': {e}",
                                    id,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // --- KV-delete prune from asset-groups ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::Delete && looks_like_kv_path(&req.path, ns) {
                if let Err(e) = store.prune_secret(&req.path).await {
                    log::warn!(
                        "resource-group prune failed for deleted KV secret '{}': {e}. \
                         Use the resource-group/reindex endpoint to clean up.",
                        req.path,
                    );
                }
            }
        }

        // --- File-delete prune from asset-groups ---
        if let Some(store) = rg_store.as_ref() {
            if req.operation == Operation::Delete {
                if let Some(id) = file_id_from_metadata_path(&req.path, ns) {
                    if let Err(e) = store.prune_file(&id).await {
                        log::warn!(
                            "resource-group prune failed for deleted file '{}': {e}. \
                             Use the resource-group/reindex endpoint to clean up.",
                            id,
                        );
                    }
                }
            }
        }

        let _ = resp;
        Err(RvError::ErrHandlerDefault)
    }
}

impl PolicyStore {
    /// Upgrade the weak Core reference and fetch the resource-group
    /// store, if the subsystem is loaded. Returns `None` otherwise —
    /// callers treat that as "no asset-group integration this turn".
    fn resource_group_store(&self) -> Option<Arc<ResourceGroupStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager()
            .get_module::<ResourceGroupModule>("resource-group")?;
        module.store()
    }

    /// Upgrade the weak Core reference and fetch the owner store from
    /// the identity module. Returns `None` when the subsystem is not
    /// loaded — callers treat that as "no per-user-scoping this turn".
    fn owner_store(&self) -> Option<Arc<OwnerStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")?;
        module.owner_store()
    }

    /// Probe whether `auth` is permitted to perform `op` on `path`.
    ///
    /// Runs the same per-target resolution and ACL evaluation as
    /// `post_auth` — asset groups, owner record, and active shares
    /// are all consulted — but in a dry-run mode that doesn't mutate
    /// anything and doesn't care about side-effects. Intended for
    /// handler code that needs to preview an authorization decision
    /// against a *different* target than the one that triggered the
    /// current request (e.g., the asset-group read handler deciding
    /// whether to redact a member the caller can't see).
    ///
    /// Returns `Ok(false)` on any resolution error so a failure
    /// silently narrows access rather than leaking it.
    pub async fn can_operate(
        &self,
        auth: &crate::logical::Auth,
        path: &str,
        op: Operation,
        ns_path: Option<&str>,
    ) -> bool {
        if auth.policies.is_empty() {
            return false;
        }

        // `ns_path` is the namespace `path` belongs to, when the caller knows
        // it. The owner / asset-group / share lookups key on the target's
        // *mount-relative* name, so they cannot strip a `<ns>/` prefix they
        // were never told about: passing `None` for a namespaced target
        // resolves no owner and no shares, which fail-closes every scope-gated
        // rule and silently strips capabilities the caller genuinely holds.
        // That is exactly how `capabilities-self` came to under-report
        // share-derived `update` for tenants.
        //
        // `None` remains correct for a root-scoped target, and for the
        // asset-group member-redaction previews that pass mount-relative paths
        // — those stay namespace-blind, which can only narrow a preview, never
        // widen it (tracked as the asset-group follow-up).
        let asset_groups = resolve_asset_groups(&self.core, path, ns_path).await;
        let asset_owner = resolve_asset_owner(&self.core, path, ns_path).await;

        let mut req = Request::default();
        req.path = path.to_string();
        req.operation = op;
        req.auth = Some(auth.clone());
        req.namespace_path = ns_path.filter(|p| !p.is_empty()).map(|p| p.to_string());
        req.asset_groups = asset_groups;
        req.asset_owner = asset_owner;
        req.target_shared_caps = resolve_target_shared_caps(&self.core, &req).await;

        let acl = match self
            .new_acl_for_request(&auth.policies, None, auth, ns_path)
            .await
        {
            Ok(a) => a,
            Err(_) => return false,
        };
        // `check_only=false` is required — with `true`, `Permissions::check`
        // short-circuits without setting `allowed`, always returning
        // `allowed=false`. The full gate is cheap for a read probe.
        acl.allow_operation(&req, false).map(|r| r.allowed).unwrap_or(false)
    }

    /// Upgrade the weak Core reference and fetch the share store from
    /// the identity module. Returns `None` when the subsystem is not
    /// loaded.
    fn share_store(&self) -> Option<Arc<ShareStore>> {
        let core = self.core.upgrade()?;
        let module = core
            .module_manager()
            .get_module::<IdentityModule>("identity")?;
        module.share_store()
    }
}

/// Filter a list response's `keys` array down to entries that are
/// members of any asset-group in `filter_groups`. The full logical
/// path of each key is reconstructed by joining `list_path` with the
/// key; `ResourceGroupStore::groups_for_resource` /
/// `groups_for_secret` do the membership lookup. Unknown paths and
/// folder entries (trailing slash) are dropped.
async fn filter_list_response(
    response: &mut Response,
    list_path: &str,
    filter_groups: &[String],
    store: &Arc<ResourceGroupStore>,
    ns_path: Option<&str>,
) {
    let Some(data) = response.data.as_mut() else { return };
    let Some(keys_val) = data.get_mut("keys") else { return };
    let Some(keys_arr) = keys_val.as_array() else { return };

    let prefix = if list_path.ends_with('/') {
        list_path.to_string()
    } else {
        format!("{list_path}/")
    };

    let mut kept: Vec<Value> = Vec::with_capacity(keys_arr.len());
    for v in keys_arr.iter() {
        let Some(k) = v.as_str() else { continue };
        if k.ends_with('/') {
            // Folders don't have a single logical path to look up.
            // Drop them from filtered output to avoid exposing
            // subtree structure the caller shouldn't see via this
            // group grant.
            continue;
        }
        let full = format!("{prefix}{k}");
        let groups = resolve_groups_for_any(store, &full, ns_path).await;
        if groups.iter().any(|g| filter_groups.iter().any(|f| f == g)) {
            kept.push(v.clone());
        }
    }

    *keys_val = Value::Array(kept);
}

/// Narrow a LIST response's `keys` array to entries that match any
/// active ownership scope:
///
/// - `owner`: each key's resolved owner matches the caller's
///   `entity_id`.
/// - `shared`: an explicit `SecretShare` grants the caller any
///   capability on the key. `SecretShare` presence alone is enough
///   for list inclusion — the shared `list` capability is not
///   separately required, matching how `list_shares_for_grantee`
///   surfaces "what is shared with me?".
///
/// Folder keys (trailing `/`) are dropped since they have no single
/// owner or share record. A key surviving *any* active scope is kept
/// (scopes OR together).
async fn filter_list_by_ownership(
    response: &mut Response,
    list_path: &str,
    filter_scopes: &[String],
    caller_entity_id: &str,
    store: &Arc<OwnerStore>,
    share_store: Option<&Arc<ShareStore>>,
    ns_path: Option<&str>,
) {
    let Some(data) = response.data.as_mut() else { return };
    let Some(keys_val) = data.get_mut("keys") else { return };
    let Some(keys_arr) = keys_val.as_array() else { return };

    let want_owner = filter_scopes.iter().any(|s| s == "owner");
    let want_shared = filter_scopes.iter().any(|s| s == "shared");

    let prefix = if list_path.ends_with('/') {
        list_path.to_string()
    } else {
        format!("{list_path}/")
    };

    let mut kept: Vec<Value> = Vec::with_capacity(keys_arr.len());
    for v in keys_arr.iter() {
        let Some(k) = v.as_str() else { continue };
        if k.ends_with('/') {
            continue;
        }
        let full = format!("{prefix}{k}");
        // `full` is a rewritten request path in child namespaces; scope it
        // to the canonical owner/share key so lookups hit the records
        // stamped by `post_route` / `create_share`.
        let scoped = OwnerStore::canonicalize_kv_path_scoped(&full, ns_path)
            .unwrap_or_else(|| full.clone());

        if caller_entity_id.is_empty() {
            continue;
        }

        let mut included = false;

        if want_owner {
            // Try both owner lookups: a key may be a KV secret or a
            // resource. Either match is sufficient.
            if let Ok(Some(rec)) = store.get_kv_owner(&scoped).await {
                if rec.entity_id == caller_entity_id {
                    included = true;
                }
            }
            if !included {
                if let Some(name) = resource_name_from_path(&full, ns_path) {
                    if let Ok(Some(rec)) = store.get_resource_owner(&name).await {
                        if rec.entity_id == caller_entity_id {
                            included = true;
                        }
                    }
                }
            }
        }

        if !included && want_shared {
            if let Some(sstore) = share_store {
                if let Ok(caps) = sstore
                    .shared_capabilities(ShareTargetKind::KvSecret, &scoped, caller_entity_id)
                    .await
                {
                    if !caps.is_empty() {
                        included = true;
                    }
                }
                if !included {
                    if let Some(name) = resource_name_from_path(&full, ns_path) {
                        if let Ok(caps) = sstore
                            .shared_capabilities(ShareTargetKind::Resource, &name, caller_entity_id)
                            .await
                        {
                            if !caps.is_empty() {
                                included = true;
                            }
                        }
                    }
                }
            }
        }

        if included {
            kept.push(v.clone());
        }
    }

    *keys_val = Value::Array(kept);
}

/// Look up asset-group membership for any target path — tries the
/// resource-name extraction first (for `resources/resources/<name>`
/// and `resources/secrets/<name>/...`), then falls back to the
/// secret-index (treating the path as a KV path). Mirrors
/// `resolve_asset_groups`.
async fn resolve_groups_for_any(
    store: &Arc<ResourceGroupStore>,
    path: &str,
    ns_path: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(name) = resource_name_from_path(path, ns_path) {
        if let Ok(groups) = store.groups_for_resource(&name).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }
    if looks_like_kv_path(path, ns_path) {
        if let Ok(groups) = store.groups_for_secret(path).await {
            for g in groups {
                if !out.iter().any(|x| x == &g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod implicit_rustion_grant_tests {
    use super::super::policy::Capability;
    use super::*;

    fn rule<'a>(p: &'a Policy, path: &str) -> Option<&'a super::super::policy::PolicyPathRules> {
        p.paths.iter().find(|r| r.path == path)
    }

    /// A namespace-bound token carries only the implicit policies, and
    /// `rustion/` is root-owned — `refuse_cross_namespace_paths` rejects any
    /// tenant-authored rule naming it. Without these grants such a token
    /// cannot resolve the effective transport, and the connect path used to
    /// read that 403 as "no policy" and dial direct: a `rustion-required`
    /// resource was silently reachable over a direct dial.
    #[test]
    fn namespace_self_grants_the_rustion_transport_resolvers() {
        let p = &*NAMESPACE_SELF_POLICY_PARSED;

        for path in ["rustion/policy/effective", "rustion/dispatcher/preview"] {
            let r = rule(p, path).unwrap_or_else(|| panic!("{path} must be granted"));
            assert!(
                r.capabilities.contains(&Capability::Update),
                "{path} is a POST endpoint, so it needs `update`"
            );
        }

        // The brokered dial verifies the bastion's transport pin off the
        // target record; without `read` here the hop degrades to unpinned TOFU.
        let r = rule(p, "rustion/targets/+").expect("rustion/targets/+ must be granted");
        assert!(r.capabilities.contains(&Capability::Read));
        assert!(r.has_segment_wildcards, "one segment only — never a prefix over the fleet");

        // LIST over the fleet stays withheld: a tenant resolves only the
        // bastions the dispatcher already named for them.
        assert!(rule(p, "rustion/targets").is_none());
        assert!(rule(p, "rustion/targets/").is_none());
        assert!(rule(p, "rustion/targets/*").is_none());
    }

    #[test]
    fn namespace_self_grants_the_gated_session_lifecycle() {
        let p = &*NAMESPACE_SELF_POLICY_PARSED;

        // Both open routes run their own per-resource `connect`/`read`/owner/
        // share gate (`may_connect_resource`), so these reach no resource the
        // caller couldn't already reach. v1 is granted because it is the route
        // brokered RDP and the client-resolved SSH kinds still take; its
        // unbound shape is separately gated on `sudo`, which is NOT granted
        // here (see `namespace_self_grants_no_sudo_on_rustion`).
        for path in [
            "rustion/session/open",
            "rustion/v2/session/open",
            "rustion/session/renew",
            "rustion/session/kill",
        ] {
            let r = rule(p, path).unwrap_or_else(|| panic!("{path} must be granted"));
            assert!(r.capabilities.contains(&Capability::Update));
        }

        // No wildcard may widen the set beyond these named endpoints — a
        // prefix rule would pull in `master/*`, `policy/global`, the target
        // registry writes, and the recording store.
        assert!(
            !p.paths.iter().any(|r| r.path.starts_with("rustion") && r.is_prefix),
            "no prefix rule over `rustion/` — every grant is a named endpoint"
        );
    }

    /// The unbound `session/open` shape (no `resource_id`: arbitrary target
    /// host, caller-supplied credential material) has no object to authorize
    /// against, so the handler requires `sudo`. The tenant baseline must never
    /// confer it, or the grant above would reopen the fleet-proxy hole.
    #[test]
    fn namespace_self_grants_no_sudo_on_rustion() {
        for p in [&*NAMESPACE_SELF_POLICY_PARSED, &Policy::from_str(DEFAULT_POLICY).unwrap()] {
            for r in p.paths.iter().filter(|r| r.path.starts_with("rustion")) {
                assert!(
                    !r.capabilities.contains(&Capability::Sudo),
                    "{} must not carry sudo",
                    r.path
                );
            }
        }
    }

    /// The root-namespace equivalent: a share-grantee needs the resolvers for
    /// the same reason, and `read_effective_policy` now fails closed when it
    /// can't reach them.
    #[test]
    fn default_policy_grants_the_read_only_resolvers_only() {
        let p = Policy::from_str(DEFAULT_POLICY).expect("built-in default policy must parse");

        for path in ["rustion/policy/effective", "rustion/dispatcher/preview"] {
            let r = rule(&p, path).unwrap_or_else(|| panic!("{path} must be granted"));
            assert!(r.capabilities.contains(&Capability::Update));
        }
        assert!(rule(&p, "rustion/targets/+").is_some());

        // Session endpoints are NOT in the root-namespace baseline: an operator
        // there grants those explicitly (see features/connect-only-access.md).
        // Only a namespace-bound token, which cannot be granted `rustion/*` by
        // any policy it could author, gets them implicitly.
        assert!(rule(&p, "rustion/v2/session/open").is_none());
        assert!(rule(&p, "rustion/session/open").is_none());
    }

    const CONNECT_ENDPOINTS: [&str; 3] = [
        "resources/v2/connect/mfa/begin",
        "resources/v2/connect/mfa/verify",
        "resources/v2/connect/authorize",
    ];

    /// The GUI calls `connect/mfa/begin` on *every* Connect — the server, not
    /// the host, decides whether a profile is gated. Ungranted, that first
    /// call 403s and Connect dies before `session/open` is ever reached, for
    /// every non-root principal including one holding `connect` on the
    /// resource.
    #[test]
    fn both_baselines_grant_the_connect_endpoints() {
        let default = Policy::from_str(DEFAULT_POLICY).expect("default policy must parse");
        for path in CONNECT_ENDPOINTS {
            let r = rule(&default, path).unwrap_or_else(|| panic!("{path} must be granted"));
            assert!(
                r.capabilities.contains(&Capability::Update),
                "{path} is a POST endpoint, so it needs `update`"
            );
        }

        // Tenant side must be TEMPLATED: `resources/` is namespace-rewritten
        // (unlike `rustion/`), so a bare rule silently never matches.
        let shared = &*NAMESPACE_SHARED_POLICY_PARSED;
        for path in CONNECT_ENDPOINTS {
            assert!(
                rule(shared, path).is_none(),
                "{path} must not be granted bare — the request arrives as `<ns>/{path}`"
            );
            let templated = format!("{{{{namespace.path}}}}/{path}");
            let r = rule(shared, &templated)
                .unwrap_or_else(|| panic!("{templated} must be granted"));
            assert!(r.capabilities.contains(&Capability::Update));
        }
    }

    /// Every baseline rule that reaches `resources/` must carry `connect`, or
    /// the capability is unreachable through it — including for an owner,
    /// whose access never involved a share at all.
    #[test]
    fn resource_baselines_carry_connect() {
        let default = Policy::from_str(DEFAULT_POLICY).unwrap();
        let standard = Policy::from_str(STANDARD_USER_POLICY).unwrap();
        let readonly = Policy::from_str(STANDARD_USER_READONLY_POLICY).unwrap();

        for (name, p, path) in [
            ("default", &default, "resources/"),
            ("standard-user", &standard, "resources/"),
            ("standard-user-readonly", &readonly, "resources/"),
        ] {
            let r = rule(p, path).unwrap_or_else(|| panic!("{name} must rule on {path}"));
            assert!(
                r.capabilities.contains(&Capability::Connect),
                "{name}'s `resources/*` rule must carry `connect`"
            );
        }

        let shared = &*NAMESPACE_SHARED_POLICY_PARSED;
        let r = rule(shared, "{{namespace.path}}/resources/").expect("tenant resources rule");
        assert!(r.capabilities.contains(&Capability::Connect));
    }

    /// `shared-access` must reach objects through a share and through nothing
    /// else. Every rule that names an object path carries `scopes = ["shared"]`
    /// — the two exceptions are the asset-group *list* (the handler narrows the
    /// response itself) and the connect-time endpoints (which are not object
    /// paths at all, and re-authorize the named resource server-side).
    #[test]
    fn shared_access_grants_only_through_a_share() {
        let p = Policy::from_str(SHARED_ACCESS_POLICY).expect("shared-access must parse");
        assert!(p.templated, "shared-access is templated on {{{{request.namespace}}}}");

        let ungated_by_design = [
            "{{request.namespace}}/resource-group/groups",
            "{{request.namespace}}/resources/v2/connect/mfa/begin",
            "{{request.namespace}}/resources/v2/connect/mfa/verify",
            "{{request.namespace}}/resources/v2/connect/authorize",
        ];
        for r in p.paths.iter() {
            if ungated_by_design.contains(&r.path.as_str()) {
                continue;
            }
            assert_eq!(
                r.scopes,
                vec!["shared".to_string()],
                "{} must be share-scoped, and must not carry `owner`",
                r.path,
            );
        }
    }

    /// Delete is the capability that separates "use what I was given" from
    /// "administer someone else's inventory". A share must never convey it.
    #[test]
    fn shared_access_withholds_delete_and_sudo() {
        let p = Policy::from_str(SHARED_ACCESS_POLICY).unwrap();
        for r in p.paths.iter() {
            assert!(!r.capabilities.contains(&Capability::Delete), "{} grants delete", r.path);
            assert!(!r.capabilities.contains(&Capability::Sudo), "{} grants sudo", r.path);
        }
    }

    /// Every object rule is written against `{{request.namespace}}`, not
    /// `{{namespace.path}}`: the whole point is to address the namespace the
    /// *request* names, which for a root-bound principal operating through a
    /// cross-namespace assignment is not the one their token is bound to.
    #[test]
    fn shared_access_templates_on_the_request_namespace() {
        let p = Policy::from_str(SHARED_ACCESS_POLICY).unwrap();
        for r in p.paths.iter() {
            assert!(
                r.path.starts_with("{{request.namespace}}/"),
                "{} must be namespace-templated, or it silently never matches \
                 inside a namespace",
                r.path,
            );
            assert!(
                !r.path.contains("{{namespace.path}}"),
                "{} must not use the token-binding template",
                r.path,
            );
        }
    }

    /// A resource share is useless without `connect`, and `connect` must be
    /// carried by the rule for the scope gate to be able to demand it on the
    /// share itself.
    #[test]
    fn shared_access_carries_connect_on_resources() {
        let p = Policy::from_str(SHARED_ACCESS_POLICY).unwrap();
        let r = rule(&p, "{{request.namespace}}/resources/").expect("resources rule");
        assert!(r.capabilities.contains(&Capability::Connect));
    }
}

#[cfg(test)]
mod templating_tests {
    use super::*;

    #[test]
    fn test_substitute_path_happy_cases() {
        let got = substitute_path(
            "secret/data/users/{{username}}/*",
            "alice",
            "ent-123",
            "userpass/",
            "",
            "",
            None,
        );
        assert_eq!(got.as_deref(), Some("secret/data/users/alice/*"));

        let got = substitute_path(
            "kv/{{entity.id}}/inbox",
            "alice",
            "ent-123",
            "",
            "",
            "",
            None,
        );
        assert_eq!(got.as_deref(), Some("kv/ent-123/inbox"));

        let got = substitute_path(
            "{{auth.mount}}login",
            "alice",
            "ent-123",
            "userpass/",
            "",
            "",
            None,
        );
        assert_eq!(got.as_deref(), Some("userpass/login"));
    }

    #[test]
    fn test_substitute_path_namespace_templates() {
        // {{namespace.path}} substitutes the bound namespace path.
        let got = substitute_path(
            "{{namespace.path}}/secret/*",
            "alice",
            "ent-123",
            "userpass/",
            "engineering/platform",
            "ns-uuid-1",
            None,
        );
        assert_eq!(got.as_deref(), Some("engineering/platform/secret/*"));

        // Root namespace path is the empty string — a legitimate substitution.
        let got = substitute_path(
            "{{namespace.path}}secret/*",
            "alice",
            "ent-123",
            "userpass/",
            "",
            "",
            None,
        );
        assert_eq!(got.as_deref(), Some("secret/*"));

        // {{namespace.id}} substitutes the opaque id when present.
        let got = substitute_path(
            "audit/{{namespace.id}}",
            "alice",
            "ent-123",
            "userpass/",
            "engineering",
            "ns-uuid-1",
            None,
        );
        assert_eq!(got.as_deref(), Some("audit/ns-uuid-1"));

        // {{namespace.id}} fails closed when absent (root/login tokens).
        assert_eq!(
            substitute_path("audit/{{namespace.id}}", "alice", "ent-123", "userpass/", "", "", None),
            None
        );
    }

    /// `{{request.namespace}}` addresses the namespace the request names, and
    /// resolves to nothing at all at root — separator included, so one rule
    /// text covers both. Without swallowing that separator the root form would
    /// be `/resources/*`, which matches no request path (they carry no leading
    /// slash) and would have failed silently.
    #[test]
    fn test_substitute_path_request_namespace() {
        let sub = |path, ns| substitute_path(path, "alice", "ent-1", "userpass/", "", "", ns);

        assert_eq!(
            sub("{{request.namespace}}/resources/*", Some("dti/esi")).as_deref(),
            Some("dti/esi/resources/*"),
        );
        assert_eq!(
            sub("{{request.namespace}}/resources/*", Some("")).as_deref(),
            Some("resources/*"),
        );
        // Nested deeper than the two levels the `+`-wildcard workaround could
        // have enumerated — the template is depth-agnostic by construction.
        assert_eq!(
            sub("{{request.namespace}}/secret/data/*", Some("a/b/c/d")).as_deref(),
            Some("a/b/c/d/secret/data/*"),
        );

        // No request context (an ACL built outside the request pipeline):
        // fail closed rather than guess root, which would point a
        // tenant-scoped rule at the root mounts.
        assert_eq!(sub("{{request.namespace}}/resources/*", None), None);

        // The token-binding template keeps its old empty-at-root behaviour —
        // it does NOT swallow the separator — so policies already in the field
        // do not change meaning on upgrade.
        assert_eq!(
            substitute_path(
                "{{namespace.path}}/secret/*",
                "alice",
                "ent-1",
                "userpass/",
                "",
                "",
                Some(""),
            )
            .as_deref(),
            Some("/secret/*"),
        );
    }

    #[test]
    fn test_substitute_path_fail_closed_on_unknown_placeholder() {
        // Unknown key — typo — must drop the rule, not widen access.
        assert_eq!(
            substitute_path("secret/{{uzername}}", "alice", "ent-123", "userpass/", "", "", None),
            None
        );
    }

    #[test]
    fn test_substitute_path_fail_closed_on_missing_value() {
        // `{{username}}` but username is empty — drop.
        assert_eq!(
            substitute_path("secret/{{username}}/*", "", "ent-123", "userpass/", "", "", None),
            None
        );
        // `{{entity.id}}` but entity_id empty — drop.
        assert_eq!(
            substitute_path("secret/{{entity.id}}", "alice", "", "userpass/", "", "", None),
            None
        );
    }

    #[test]
    fn test_substitute_path_no_placeholders_is_identity() {
        assert_eq!(
            substitute_path("secret/foo/bar", "alice", "ent-123", "userpass/", "", "", None).as_deref(),
            Some("secret/foo/bar")
        );
    }

    // ── apply_templates wrapper ──────────────────────────────────────

    use crate::{
        logical::Auth,
        modules::policy::{Policy, PolicyPathRules, PolicyType},
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn policy_with_paths(paths: Vec<&str>) -> Arc<Policy> {
        let mut p = Policy::default();
        p.name = "test-templated".to_string();
        p.policy_type = PolicyType::Acl;
        p.templated = true;
        p.paths = paths
            .into_iter()
            .map(|path| {
                let mut rule = PolicyPathRules::default();
                rule.path = path.to_string();
                rule
            })
            .collect();
        Arc::new(p)
    }

    fn auth_with(
        username: Option<&str>,
        entity_id: Option<&str>,
        mount_path: Option<&str>,
        display_name: &str,
    ) -> Auth {
        let mut meta = HashMap::new();
        if let Some(u) = username {
            meta.insert("username".into(), u.into());
        }
        if let Some(e) = entity_id {
            meta.insert("entity_id".into(), e.into());
        }
        if let Some(m) = mount_path {
            meta.insert("mount_path".into(), m.into());
        }
        Auth {
            display_name: display_name.into(),
            metadata: meta,
            ..Auth::default()
        }
    }

    #[test]
    fn test_apply_templates_substitutes_in_all_paths() {
        let policy = policy_with_paths(vec![
            "secret/data/users/{{username}}/*",
            "kv/{{entity.id}}/inbox",
        ]);
        let auth = auth_with(Some("alice"), Some("ent-abc"), Some("userpass/"), "alice");
        let got = apply_templates(&policy, &auth, None).expect("policy must survive");
        let paths: Vec<&str> = got.paths.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["secret/data/users/alice/*", "kv/ent-abc/inbox"],
            "every templated path must be substituted with caller values"
        );
    }

    #[test]
    fn test_apply_templates_username_falls_back_to_display_name() {
        // No `username` metadata key, but display_name is set — apply_templates
        // must fall back so a FIDO2 or cert login with only display_name
        // still authorizes a `{{username}}` rule.
        let policy = policy_with_paths(vec!["secret/data/users/{{username}}/*"]);
        let auth = auth_with(None, Some("ent-abc"), Some("userpass/"), "bob");
        let got = apply_templates(&policy, &auth, None).expect("policy must survive");
        assert_eq!(got.paths[0].path, "secret/data/users/bob/*");
    }

    #[test]
    fn test_apply_templates_drops_individual_unresolved_rules() {
        // Two rules: one resolvable, one needs `{{auth.mount}}` which is
        // absent from metadata. The resolvable rule survives; the other
        // is dropped fail-closed, policy still contributes.
        let policy = policy_with_paths(vec![
            "secret/data/users/{{username}}/*",
            "{{auth.mount}}login",
        ]);
        let auth = auth_with(Some("alice"), Some("ent-abc"), None, "alice");
        let got = apply_templates(&policy, &auth, None).expect("at least one rule survives");
        let paths: Vec<&str> = got.paths.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["secret/data/users/alice/*"]);
    }

    #[test]
    fn test_apply_templates_returns_none_when_all_rules_drop() {
        // Every rule references something the auth doesn't have. Fail
        // closed: policy contributes no authorization.
        let policy = policy_with_paths(vec![
            "{{auth.mount}}login",
            "secret/{{entity.id}}",
        ]);
        let auth = auth_with(Some("alice"), None, None, "alice");
        assert!(
            apply_templates(&policy, &auth, None).is_none(),
            "all-rules-dropped must return None so the policy grants nothing"
        );
    }

    #[test]
    fn test_apply_templates_preserves_rule_capabilities() {
        // Rules carry more than just `path` — capabilities / scopes /
        // groups must survive the substitution.
        let mut policy = Policy::default();
        policy.name = "keep-fields".into();
        policy.templated = true;
        let mut rule = PolicyPathRules::default();
        rule.path = "secret/data/users/{{username}}/*".into();
        rule.capabilities = vec![
            crate::modules::policy::policy::Capability::Read,
            crate::modules::policy::policy::Capability::Update,
        ];
        rule.scopes = vec!["owner".into(), "shared".into()];
        policy.paths = vec![rule];

        let auth = auth_with(Some("carol"), Some("ent-c"), Some("userpass/"), "carol");
        let got = apply_templates(&Arc::new(policy), &auth, None).expect("survives");
        let r = &got.paths[0];
        assert_eq!(r.path, "secret/data/users/carol/*");
        assert_eq!(r.capabilities.len(), 2);
        assert_eq!(r.scopes, vec!["owner", "shared"]);
    }
}

#[cfg(test)]
mod mod_policy_store_tests {
    use super::{super::policy::Capability, *};
    use crate::test_utils::new_unseal_test_bastion_vault;

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_store_crud() {
        let (_bvault, core, _root_token) = new_unseal_test_bastion_vault("test_policy_store_crud").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        let policy1_name = "test-policy1";
        let policy1_hcl = r#"
        path "secret/data/test1" {
            capabilities = ["read", "list"]
        }"#;

        let policy2_name = "test-policy2";
        let policy2_hcl = r#"
        path "secret/data/test2" {
            capabilities = ["create", "delete"]
        }"#;

        let mut policy1 = Policy::from_str(policy1_hcl).unwrap();
        policy1.name = policy1_name.to_string();

        let mut policy2 = Policy::from_str(policy2_hcl).unwrap();
        policy2.name = policy2_name.to_string();

        // Set the policy
        let result = policy_store.set_policy(policy1).await;
        assert!(result.is_ok());
        let result = policy_store.set_policy(policy2).await;
        assert!(result.is_ok());

        // Verify the policy is set
        let retrieved_policy = policy_store.get_policy(policy1_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_some());
        let retrieved_policy = retrieved_policy.unwrap();
        assert_eq!(retrieved_policy.name, policy1_name);
        assert_eq!(retrieved_policy.raw, policy1_hcl);
        let retrieved_policy = policy_store.get_policy(policy2_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_some());
        let retrieved_policy = retrieved_policy.unwrap();
        assert_eq!(retrieved_policy.name, policy2_name);
        assert_eq!(retrieved_policy.raw, policy2_hcl);

        // List policies
        let policies = policy_store.list_policy(PolicyType::Acl).await.unwrap();
        assert!(policies.contains(&policy1_name.to_string()));
        assert!(policies.contains(&policy2_name.to_string()));

        // Delete the policy
        let result = policy_store.delete_policy(policy1_name, PolicyType::Acl).await;
        assert!(result.is_ok());
        let retrieved_policy = policy_store.get_policy(policy1_name, PolicyType::Acl).await.unwrap();
        assert!(retrieved_policy.is_none());

        // List policies again
        let policies = policy_store.list_policy(PolicyType::Acl).await.unwrap();
        assert!(!policies.contains(&policy1_name.to_string()));
        assert!(policies.contains(&policy2_name.to_string()));
    }

    /// Multi-tenancy self-service gap: a token bound to a non-root namespace
    /// resolves its named policies from that namespace's (initially empty)
    /// keyspace, so it would carry no grant on the self endpoints. Verify the
    /// implicit `namespace-self` policy is injected into ACL construction for
    /// namespace-bound tokens (granting the self endpoints) while leaving the
    /// root hot path — and tenant data access — untouched.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_bound_token_gets_self_service_acl() {
        use crate::logical::Auth;
        use crate::modules::namespace::token_binding::stamp_binding;

        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_ns_self_service_acl").await;
        let policy_store = PolicyStore::new(&core).await.unwrap();

        // A namespace-bound token. Its named policies (`default`, plus one that
        // does not exist) resolve to nothing in the empty `nsa` keyspace — the
        // exact "child namespace starts empty" condition.
        let mut ns_auth =
            Auth { policies: vec!["default".into(), "nonexistent".into()], ..Default::default() };
        stamp_binding(&mut ns_auth.metadata, "nsa", "uuid-nsa", false);

        let acl = policy_store
            .new_acl_for_request(&ns_auth.policies, None, &ns_auth, None)
            .await
            .unwrap();

        // Self-service endpoints are reachable despite the empty keyspace.
        for (path, cap) in [
            ("sys/capabilities-self", "update"),
            ("auth/token/lookup-self", "read"),
            ("auth/token/renew-self", "update"),
            ("auth/token/revoke-self", "update"),
            ("sys/internal/ui/resultant-acl", "read"),
            ("cubbyhole/scratch", "read"),
        ] {
            let caps = acl.capabilities(path.to_string());
            assert!(
                caps.iter().any(|c| c == cap),
                "namespace token must have `{cap}` on `{path}`, got {caps:?}"
            );
            assert!(
                !caps.iter().any(|c| c == "deny"),
                "namespace token must not be denied on `{path}`, got {caps:?}"
            );
        }

        // No privilege over-grant: tenant data paths remain denied. The
        // implicit policy only carries self/introspection endpoints.
        assert_eq!(
            acl.capabilities("secret/data/x".to_string()),
            vec!["deny".to_string()],
            "self policy must not grant tenant data access"
        );

        // The root hot path is byte-for-byte unchanged: a root-bound token
        // (no namespace binding) carrying a policy that does NOT grant the self
        // endpoints must still be denied them — the implicit policy is only
        // injected for non-root bindings.
        let mut rootonly = Policy::from_str("path \"secret/data/y\" { capabilities = [\"read\"] }").unwrap();
        rootonly.name = "rootonly".to_string();
        policy_store.set_policy(rootonly).await.unwrap();

        let root_auth = Auth { policies: vec!["rootonly".into()], ..Default::default() };
        let root_acl = policy_store
            .new_acl_for_request(&root_auth.policies, None, &root_auth, None)
            .await
            .unwrap();
        assert_eq!(
            root_acl.capabilities("sys/capabilities-self".to_string()),
            vec!["deny".to_string()],
            "root path must not gain the implicit namespace self-service policy"
        );
        assert!(
            root_acl.capabilities("secret/data/y".to_string()).iter().any(|c| c == "read"),
            "the root-bound token's own policy must still apply"
        );
    }

    /// A namespace-bound token must carry the implicit *shared-target* grant on
    /// its own namespace's mounts, scoped to that namespace and no other.
    ///
    /// Without it a tenant whose namespace has no policies of its own (the
    /// state every namespace is created in) had no rule touching
    /// `<ns>/resources/*`, so `sys/internal/ui/mounts` reported nothing and the
    /// GUI dropped the Resources / Secrets nav entries entirely.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_namespace_bound_token_gets_shared_target_acl() {
        use crate::logical::Auth;
        use crate::modules::namespace::token_binding::stamp_binding;

        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_ns_shared_target_acl").await;
        let policy_store = PolicyStore::new(&core).await.unwrap();

        let mut ns_auth = Auth { policies: vec!["default".into()], ..Default::default() };
        stamp_binding(&mut ns_auth.metadata, "dti/esi", "uuid-dti-esi", false);
        // `scope_passes` resolves the grantee from the caller's entity_id; an
        // anonymous caller can never satisfy a `shared` scope.
        ns_auth.metadata.insert("entity_id".to_string(), "entity-tina".to_string());
        let acl = policy_store
            .new_acl_for_request(&ns_auth.policies, None, &ns_auth, None)
            .await
            .unwrap();

        // The token's own namespace: the mount is reachable, which is what
        // `has_mount_access` (and therefore the GUI's nav gate) keys on.
        for mount in ["dti/esi/resources/", "dti/esi/secret/", "dti/esi/resource-group/"] {
            assert!(
                acl.has_mount_access(mount),
                "tenant must have mount access on its own `{mount}`"
            );
        }

        // Another tenant's identical mounts stay unreachable — the rules are
        // `{{namespace.path}}`-templated against this token's binding, so they
        // can never widen into a sibling namespace.
        for mount in ["dti/outro/resources/", "resources/"] {
            assert!(
                !acl.has_mount_access(mount),
                "tenant must NOT have mount access on `{mount}`"
            );
        }

        // Visibility is not access: every data rule is `scopes = ["shared"]`,
        // so a concrete read with no `SecretShare` on the request is refused.
        // (`capabilities` runs as a LIST dry-run, which by design defers scope
        // filtering, so assert against the real evaluator instead.)
        let req = Request {
            operation: Operation::Read,
            path: "dti/esi/resources/resources/db1".to_string(),
            auth: Some(ns_auth.clone()),
            ..Default::default()
        };
        assert!(
            !acl.allow_operation(&req, false).unwrap().allowed,
            "share-scoped rule must not grant a read with no active share"
        );

        // The same read succeeds once the request carries the share the
        // `shared` scope looks for, proving the rule is live and not inert.
        let shared_req = Request {
            target_shared_caps: vec!["read".to_string()],
            ..req.clone()
        };
        assert!(
            acl.allow_operation(&shared_req, false).unwrap().allowed,
            "share-scoped rule must grant a read backed by an active share"
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_load_default() {
        let (_bvault, core, _root_token) = new_unseal_test_bastion_vault("test_policy_load_default").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        // Load default ACL policies
        policy_store.load_default_acl_policy().await.unwrap();

        // Verify the default policies are loaded
        let default_policy = policy_store.get_policy("default", PolicyType::Acl).await.unwrap();
        assert!(default_policy.is_some());

        let response_wrapping_policy = policy_store.get_policy("response-wrapping", PolicyType::Acl).await.unwrap();
        assert!(response_wrapping_policy.is_some());

        let control_group_policy = policy_store.get_policy("control-group", PolicyType::Acl).await.unwrap();
        assert!(control_group_policy.is_some());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_root() {
        let (_, core, _) = new_unseal_test_bastion_vault("test_policy_root").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        // Get should return a special policy
        let root_policy = policy_store.get_policy("root", PolicyType::Token).await.unwrap();
        assert!(root_policy.is_some());
        let root_policy = root_policy.unwrap();
        assert_eq!(root_policy.name, "root");

        // Set should fail
        let result = policy_store.set_policy(Policy { name: "root".into(), ..Default::default() }).await;
        assert!(result.is_err());

        // Delete should fail
        let result = policy_store.delete_policy("root", PolicyType::Acl).await;
        assert!(result.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_new_acl() {
        let (_, core, _) = new_unseal_test_bastion_vault("test_policy_new_acl").await;

        let policy_store = PolicyStore::new(&core).await.unwrap();

        let policy1_name = "test-policy1";
        let policy1_hcl = r#"
        path "secret/data/test1/*" {
            capabilities = ["read", "list"]
        }"#;

        let policy2_name = "test-policy2";
        let policy2_hcl = r#"
        path "secret/data/test2" {
            capabilities = ["create", "delete"]
        }"#;

        let mut policy1 = Policy::from_str(policy1_hcl).unwrap();
        policy1.name = policy1_name.to_string();

        let mut policy2 = Policy::from_str(policy2_hcl).unwrap();
        policy2.name = policy2_name.to_string();

        // Set the policy
        policy_store.set_policy(policy1).await.unwrap();
        policy_store.set_policy(policy2).await.unwrap();

        // Load default ACL policies
        policy_store.load_default_acl_policy().await.unwrap();

        // Create a new ACL
        let acl = policy_store.new_acl(&[policy1_name.to_string(), policy2_name.to_string()], None).await.unwrap();

        // Verify the ACL contains the policies
        assert_eq!(
            acl.prefix_rules.get_ancestor_value("secret/data/test1/kk/vv").unwrap().capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits()
        );
        assert_eq!(
            acl.exact_rules.get("secret/data/test2").unwrap().capabilities_bitmap,
            Capability::Create.to_bits() | Capability::Delete.to_bits()
        );
    }

    /// `policy_type_map` is per-node and in-memory: built once in
    /// `PolicyStore::new`, then only by the writes this node itself served. A
    /// policy created against another cluster member replicates its bytes
    /// through Raft but never reaches this node's map, so a `PolicyType::Token`
    /// lookup misses for a policy that plainly exists. It must read through to
    /// the replicated ACL keyspace rather than fail the request.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_token_policy_reads_through_a_cold_type_map() {
        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_policy_cold_type_map").await;
        let policy_store = PolicyStore::new(&core).await.unwrap();

        let mut peer = Policy::from_str(
            r#"path "secret/data/peer/*" { capabilities = ["read"] }"#,
        )
        .unwrap();
        peer.name = "peer-written".to_string();
        policy_store.set_policy(peer).await.unwrap();

        // Reproduce the peer-node write: the bytes sit in the replicated ACL
        // keyspace, but this node never served the write, so neither its type
        // map nor its policy LRU has ever heard of the name.
        let index = policy_store.cache_key("peer-written");
        policy_store.policy_type_map.remove(&index);
        policy_store.remove_token_policy_cache(&index).unwrap();

        let got = policy_store
            .get_policy("peer-written", PolicyType::Token)
            .await
            .expect("a cold type map must not fail the lookup");
        assert!(got.is_some(), "Token lookup must read through to the replicated ACL keyspace");
        assert_eq!(got.unwrap().name, "peer-written");
        assert_eq!(
            policy_store.policy_type_map.get(&index).map(|v| *v),
            Some(PolicyType::Acl),
            "the resolved type must be memoized so later lookups take the fast path"
        );
    }

    /// A root-bound token whose policy list names a policy that does not exist
    /// in the root namespace must be denied, not error. This is the shape of a
    /// common operator slip: the policy was created inside a child namespace
    /// while the auth role handing out its name lives at the root, so the name
    /// resolves nowhere on the request's path. `get_policy_ns` already skipped
    /// unresolvable names for namespace-bound tokens; the root path used to
    /// return `unable to get the barrier subview for policy type token`, which
    /// reached the caller as an opaque HTTP 500.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_root_bound_token_with_unresolvable_policy_is_denied_not_error() {
        use crate::logical::Auth;

        let (_bvault, core, _root_token) =
            new_unseal_test_bastion_vault("test_policy_unresolvable_root").await;
        let policy_store = PolicyStore::new(&core).await.unwrap();

        assert!(
            policy_store
                .get_policy("lives-in-a-child-namespace", PolicyType::Token)
                .await
                .expect("an unresolvable policy name must not be an error")
                .is_none(),
            "an unresolvable policy name must resolve to None so the caller can skip it"
        );

        let auth =
            Auth { policies: vec!["lives-in-a-child-namespace".into()], ..Default::default() };
        let acl = policy_store
            .new_acl_for_request(&auth.policies, None, &auth, None)
            .await
            .expect("ACL construction must not fail because a named policy is unresolvable");

        assert_eq!(
            acl.capabilities("dti/esi/secret/data/github/nessus".to_string()),
            vec!["deny".to_string()],
            "the request must be denied on its merits, not fail with a server error"
        );
    }
}
