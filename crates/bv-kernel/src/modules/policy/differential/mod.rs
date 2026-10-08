//! T31 Phase 3.3 — the production evaluator, now a thin host over
//! `bv-policy-core`, against [`legacy`], a frozen copy of the evaluator as
//! it was before it delegated. They must agree on every generated policy set
//! and request, in both enforcement and capability-probe mode, down to the
//! granting-policy names and the LIST filter entries and their order.
//!
//! The Kani proofs (`cargo kani -p bv-policy-core`) are about the core over
//! every answer the index could give; this suite is what ties those answers
//! to real strings: HCL parsing, the radix tries, the segment-wildcard map,
//! case-folded parameter keys, glob-matched JSON values and group names.
//!
//! `PROPTEST_CASES` sets the case count (default 1024 here, so the normal
//! `cargo nextest run -p bv-kernel --lib` stays fast); the Phase 3 gate is
//! `PROPTEST_CASES=100000`. The seed is fixed unless `PROPTEST_RNG_SEED`
//! is set, so a default run is deterministic.

mod legacy;

use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use proptest::{prelude::*, test_runner::RngSeed};
use serde_json::{json, Map, Value};
use strum::IntoEnumIterator;

use super::{
    acl::{segment_wildcard_matches, ACLResults, ACL},
    policy::Capability,
    Permissions, Policy,
};
use crate::logical::{auth::PolicyInfo, Auth, Operation, Request};

fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 1024;
    }
    if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
        config.rng_seed = RngSeed::Fixed(0x0731_2026);
    }
    config
}

// ── Generated policies ─────────────────────────────────────────────

/// Rule path segments. A small alphabet on purpose, so generated rules
/// collide (exercising `Permissions::merge`), nest (prefix vs exact vs
/// segment wildcard) and hit the edge cases: the empty segment a trailing
/// `/` produces, `+`, a string-prefix pair (`a` / `ab`), and a literal
/// segment containing `+` (which moves the specificity key).
const RULE_SEGMENTS: &[&str] = &["a", "ab", "b", "+", "", "x+y"];
const REQUEST_SEGMENTS: &[&str] = &["a", "ab", "abc", "b", "+", "", "x+y"];
const CAPS: &[&str] = &["deny", "create", "read", "update", "delete", "list", "sudo", "patch", "connect"];
const OLD_STYLE: &[&str] = &["deny", "read", "write", "sudo"];
const GROUPS: &[&str] = &["g1", "G2", " g1 ", "g3"];
const SCOPES: &[&str] = &["owner", "shared", "any", "bogus", "OWNER"];
const REQUIRED: &[&str] = &["env", "Foo"];
const PARAM_KEYS: &[&str] = &["env", "foo", "*", "Bar"];
const PARAM_LISTS: &[&str] = &["[]", "[\"prod\"]", "[\"dev*\"]", "[1]", "[true]"];
const TTLS: &[u64] = &[0, 50, 100, 300];

#[derive(Debug, Clone)]
struct RuleModel {
    path: String,
    caps: Vec<&'static str>,
    old_style: Option<&'static str>,
    groups: Vec<&'static str>,
    scopes: Vec<&'static str>,
    required: Vec<&'static str>,
    allowed: Option<Vec<(&'static str, &'static str)>>,
    denied: Option<Vec<(&'static str, &'static str)>>,
    ttl: Option<(u64, u64)>,
}

fn arb_rule_path() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(prop::sample::select(RULE_SEGMENTS), 1..=3),
        prop::bool::weighted(0.4),
        prop::bool::weighted(0.1),
    )
        .prop_map(|(segments, glob, leading_slash)| {
            let mut path = segments.join("/");
            if glob {
                path.push('*');
            }
            if leading_slash {
                path.insert(0, '/');
            }
            path
        })
        .prop_filter("the policy parser rejects `+*`", |p| !p.contains("+*"))
}

fn arb_param_map() -> impl Strategy<Value = Vec<(&'static str, &'static str)>> {
    prop::collection::vec((prop::sample::select(PARAM_KEYS), prop::sample::select(PARAM_LISTS)), 0..=3).prop_map(
        |mut entries| {
            let mut seen = Vec::new();
            entries.retain(|(k, _)| {
                let fresh = !seen.contains(k);
                seen.push(*k);
                fresh
            });
            entries
        },
    )
}

fn arb_filter(values: &'static [&'static str]) -> impl Strategy<Value = Vec<&'static str>> {
    prop_oneof![3 => Just(Vec::new()), 1 => prop::sample::subsequence(values, 1..=2)]
}

fn arb_rule() -> impl Strategy<Value = RuleModel> {
    (
        arb_rule_path(),
        prop::sample::subsequence(CAPS, 0..=4),
        prop::option::weighted(0.1, prop::sample::select(OLD_STYLE)),
        arb_filter(GROUPS),
        arb_filter(SCOPES),
        arb_filter(REQUIRED),
        prop::option::weighted(0.25, arb_param_map()),
        prop::option::weighted(0.25, arb_param_map()),
        prop::option::weighted(0.1, (prop::sample::select(TTLS), prop::sample::select(TTLS))),
    )
        .prop_map(|(path, caps, old_style, groups, scopes, required, allowed, denied, ttl)| RuleModel {
            path,
            caps,
            old_style,
            groups,
            scopes,
            required,
            allowed,
            denied,
            ttl,
        })
}

fn arb_policy_set() -> impl Strategy<Value = Vec<Vec<RuleModel>>> {
    prop::collection::vec(prop::collection::vec(arb_rule(), 1..=4), 1..=3)
}

fn quoted(items: &[&str]) -> String {
    items.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ")
}

fn hcl(name: &str, rules: &[RuleModel]) -> String {
    let mut s = format!("name = \"{name}\"\n");
    for r in rules {
        s += &format!("path \"{}\" {{\n", r.path);
        s += &format!("  capabilities = [{}]\n", quoted(&r.caps));
        if let Some(old) = r.old_style {
            s += &format!("  policy = \"{old}\"\n");
        }
        for (key, values) in [("groups", &r.groups), ("scopes", &r.scopes), ("required_parameters", &r.required)] {
            if !values.is_empty() {
                s += &format!("  {key} = [{}]\n", quoted(values));
            }
        }
        for (key, map) in [("allowed_parameters", &r.allowed), ("denied_parameters", &r.denied)] {
            if let Some(map) = map {
                s += &format!("  {key} = {{\n");
                for (k, v) in map {
                    s += &format!("    \"{k}\" = {v}\n");
                }
                s += "  }\n";
            }
        }
        if let Some((min, max)) = r.ttl {
            s += &format!("  min_wrapping_ttl = {min}\n  max_wrapping_ttl = {max}\n");
        }
        s += "}\n";
    }
    s
}

fn parse_set(set: &[Vec<RuleModel>]) -> Vec<Arc<Policy>> {
    set.iter()
        .enumerate()
        .map(|(i, rules)| {
            let text = hcl(&format!("p{i}"), rules);
            Arc::new(
                Policy::from_str(&text).unwrap_or_else(|e| panic!("generated policy did not parse ({e}):\n{text}")),
            )
        })
        .collect()
}

// ── Generated requests ─────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RequestModel {
    op: Operation,
    path: String,
    data: Option<Vec<(&'static str, &'static str)>>,
    body: Option<Vec<(&'static str, &'static str)>>,
    /// `None`: no auth. `Some(None)`: auth without an `entity_id`.
    entity: Option<Option<&'static str>>,
    asset_groups: Vec<&'static str>,
    asset_owner: &'static str,
    shared: Vec<&'static str>,
    share_override: Option<&'static str>,
}

const OPS: &[Operation] = &[
    Operation::List,
    Operation::Read,
    Operation::Write,
    Operation::Delete,
    Operation::Help,
    Operation::Renew,
    Operation::Revoke,
    Operation::Rollback,
];
const DATA_KEYS: &[&str] = &["env", "ENV", "foo", "bar", "*"];
const DATA_VALUES: &[&str] = &["prod", "dev", "devx", "1", "true"];

fn json_value(code: &str) -> Value {
    match code {
        "1" => json!(1),
        "true" => json!(true),
        s => json!(s),
    }
}

fn arb_params() -> impl Strategy<Value = Option<Vec<(&'static str, &'static str)>>> {
    prop::option::weighted(
        0.4,
        prop::collection::vec((prop::sample::select(DATA_KEYS), prop::sample::select(DATA_VALUES)), 0..=3),
    )
}

fn arb_request() -> impl Strategy<Value = RequestModel> {
    let path = (
        prop::collection::vec(prop::sample::select(REQUEST_SEGMENTS), 1..=4),
        prop::bool::weighted(0.1),
        prop::bool::weighted(0.2),
    )
        .prop_map(|(segments, leading_slash, trailing_slash)| {
            let mut path = segments.join("/");
            if trailing_slash {
                path.push('/');
            }
            if leading_slash {
                path.insert(0, '/');
            }
            path
        });
    (
        prop::sample::select(OPS),
        path,
        arb_params(),
        arb_params(),
        prop::option::of(prop::option::of(prop::sample::select(&["", "u1", "u2"][..]))),
        prop::sample::subsequence(&["g1", "G1 ", "g2"][..], 0..=2),
        prop::sample::select(&["", "u1", "u2"][..]),
        prop::sample::subsequence(&["read", "list", "update", "delete", "connect"][..], 0..=3),
        prop::option::of(prop::sample::select(&["connect", "read", ""][..])),
    )
        .prop_map(|(op, path, data, body, entity, asset_groups, asset_owner, shared, share_override)| {
            RequestModel { op, path, data, body, entity, asset_groups, asset_owner, shared, share_override }
        })
}

fn to_map(entries: &[(&str, &str)]) -> Map<String, Value> {
    entries.iter().map(|(k, v)| (k.to_string(), json_value(v))).collect()
}

fn request(m: &RequestModel) -> Request {
    let mut req = Request { operation: m.op, path: m.path.clone(), ..Default::default() };
    req.data = m.data.as_deref().map(to_map);
    req.body = m.body.as_deref().map(to_map);
    if let Some(entity) = m.entity {
        let mut auth = Auth::default();
        if let Some(id) = entity {
            auth.metadata.insert("entity_id".to_string(), id.to_string());
        }
        req.auth = Some(auth);
    }
    req.asset_groups = m.asset_groups.iter().map(|s| s.to_string()).collect();
    req.asset_owner = m.asset_owner.to_string();
    req.target_shared_caps = m.shared.iter().map(|s| s.to_string()).collect();
    req.share_capability_override = m.share_override.map(str::to_string);
    req
}

// ── Comparison ─────────────────────────────────────────────────────

type Projection = (bool, bool, bool, u32, Vec<PolicyInfo>, Vec<String>, Vec<String>);

fn project(r: &ACLResults) -> Projection {
    (
        r.allowed,
        r.root_privs,
        r.is_root,
        r.capabilities_bitmap,
        r.granting_policies.clone(),
        r.list_filter_groups.clone(),
        r.list_filter_scopes.clone(),
    )
}

/// Everything about a stored permission set that a verdict can read.
fn perm_key(p: &Permissions) -> String {
    let granting: BTreeMap<u32, Vec<PolicyInfo>> =
        p.granting_policies_map.iter().map(|e| (*e.key(), e.value().clone())).collect();
    let sorted = |m: &std::collections::HashMap<String, Vec<Value>>| {
        m.iter().collect::<BTreeMap<_, _>>().into_iter().map(|(k, v)| format!("{k}={v:?}")).collect::<Vec<_>>()
    };
    format!(
        "caps={} ttl={:?}/{:?} allowed={:?} denied={:?} required={:?} groups={:?} scopes={:?} granting={granting:?}",
        p.capabilities_bitmap,
        p.min_wrapping_ttl,
        p.max_wrapping_ttl,
        sorted(&p.allowed_parameters),
        sorted(&p.denied_parameters),
        p.required_parameters,
        p.groups,
        p.scopes,
    )
}

/// `ACL::new` (which now merges through `bv_policy_core::merge_caps`) built
/// the same index as the frozen constructor.
fn same_index(new: &ACL, old: &ACL) -> Result<(), TestCaseError> {
    use radix_trie::TrieCommon;
    let trie = |acl: &ACL, prefix: bool| {
        let t = if prefix { &acl.prefix_rules } else { &acl.exact_rules };
        t.iter().map(|(k, v)| (k.clone(), perm_key(v))).collect::<Vec<_>>()
    };
    let wildcards = |acl: &ACL| {
        acl.segment_wildcard_paths.iter().map(|e| (e.key().clone(), perm_key(e.value()))).collect::<BTreeMap<_, _>>()
    };
    let gated = |acl: &ACL| {
        acl.grouped_rules
            .iter()
            .map(|r| (r.path.clone(), r.is_prefix, r.has_segment_wildcards, perm_key(&r.permissions)))
            .collect::<Vec<_>>()
    };
    let scoped = |acl: &ACL| {
        acl.scoped_rules
            .iter()
            .map(|r| (r.path.clone(), r.is_prefix, r.has_segment_wildcards, perm_key(&r.permissions)))
            .collect::<Vec<_>>()
    };
    prop_assert_eq!(new.root, old.root);
    prop_assert_eq!(trie(new, false), trie(old, false));
    prop_assert_eq!(trie(new, true), trie(old, true));
    prop_assert_eq!(wildcards(new), wildcards(old));
    prop_assert_eq!(gated(new), gated(old));
    prop_assert_eq!(scoped(new), scoped(old));
    Ok(())
}

fn agree_on(new: &ACL, old: &ACL, policies: &[Arc<Policy>], m: &RequestModel) -> Result<(), TestCaseError> {
    let req = request(m);
    for check_only in [false, true] {
        prop_assert_eq!(
            project(&new.allow_operation(&req, check_only).unwrap()),
            project(&legacy::allow_operation(old, &req, check_only).unwrap()),
            "allow_operation(check_only = {})",
            check_only
        );
        for policy in policies {
            for pr in &policy.paths {
                prop_assert_eq!(
                    project(&pr.permissions.check(&req, check_only).unwrap()),
                    project(&legacy::check(&pr.permissions, &req, check_only).unwrap()),
                    "Permissions::check on {:?} (check_only = {})",
                    pr.path,
                    check_only
                );
            }
        }
    }
    prop_assert_eq!(new.capabilities(req.path.clone()), legacy::capabilities(old, &req.path));
    prop_assert_eq!(new.scope_gated_non_contributors(&req), legacy::scope_gated_non_contributors(old, &req));
    // `has_mount_access` is called with mount paths, which always contain a
    // `/`; on a path without one its bare-mount heuristic underflows
    // `path_parts.len() - 2` (in both versions alike).
    if req.path.contains('/') {
        prop_assert_eq!(new.has_mount_access(&req.path), legacy::has_mount_access(old, &req.path));
    }
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    /// The anti-drift net: same verdict, same capabilities, same granting
    /// policies, same LIST filters, same diagnostics, same index.
    #[test]
    fn production_agrees_with_the_frozen_evaluator(set in arb_policy_set(), requests in prop::collection::vec(arb_request(), 1..=4)) {
        let policies = parse_set(&set);
        match (ACL::new(&policies), legacy::new_acl(&policies)) {
            (Ok(new), Ok(old)) => {
                same_index(&new, &old)?;
                for m in &requests {
                    agree_on(&new, &old, &policies, m)?;
                }
            }
            (new, old) => prop_assert!(false, "constructors disagree: new ok = {}, frozen ok = {}", new.is_ok(), old.is_ok()),
        }
    }

    /// The segment matcher the gated and scoped layers (and the dry-run's
    /// `locate_match`) use, against the frozen one, on every shape.
    #[test]
    fn segment_matcher_agrees_with_the_frozen_one(rule in arb_rule_path(), is_prefix in any::<bool>(), req in arb_request()) {
        let rule = rule.trim_start_matches('/').to_string();
        prop_assert_eq!(segment_wildcard_matches(&rule, is_prefix, &req.path), legacy::segment_wildcard_matches(&rule, is_prefix, &req.path));
    }
}

/// The root policy, alone and alongside another policy, through both
/// constructors.
#[test]
fn root_acls_agree() {
    let root = Arc::new(Policy { name: "root".into(), ..Default::default() });
    let other = Arc::new(Policy::from_str(r#"path "a/*" { capabilities = ["read"] }"#).unwrap());
    let acl = ACL::new(std::slice::from_ref(&root)).unwrap();
    let old = legacy::new_acl(std::slice::from_ref(&root)).unwrap();
    for op in OPS {
        let req = Request { operation: *op, path: "a/b".into(), ..Default::default() };
        for check_only in [false, true] {
            assert_eq!(
                project(&acl.allow_operation(&req, check_only).unwrap()),
                project(&legacy::allow_operation(&old, &req, check_only).unwrap())
            );
        }
    }
    assert!(ACL::new(&[root.clone(), other.clone()]).is_err());
    assert!(legacy::new_acl(&[root, other]).is_err());
}

/// Guards the "same bit layout" note in `bv-policy-core`: the core decides on
/// raw bitmaps, so every `Capability` must have the bit the core's constant
/// names, and a new capability must get a constant.
#[test]
fn capability_bit_layout_matches_core() {
    let pairs = [
        (Capability::Deny, bv_policy_core::CAP_DENY),
        (Capability::Create, bv_policy_core::CAP_CREATE),
        (Capability::Read, bv_policy_core::CAP_READ),
        (Capability::Update, bv_policy_core::CAP_UPDATE),
        (Capability::Delete, bv_policy_core::CAP_DELETE),
        (Capability::List, bv_policy_core::CAP_LIST),
        (Capability::Sudo, bv_policy_core::CAP_SUDO),
        (Capability::Patch, bv_policy_core::CAP_PATCH),
        (Capability::Root, bv_policy_core::CAP_ROOT),
        (Capability::Connect, bv_policy_core::CAP_CONNECT),
    ];
    for (cap, bit) in pairs {
        assert_eq!(cap.to_bits(), bit, "{cap}");
    }
    assert_eq!(Capability::iter().count(), pairs.len(), "a Capability was added without a bv-policy-core constant");
}

// ── Open defects, pinned ───────────────────────────────────────────
//
// Characterizations, not endorsements: each asserts what the evaluator does
// *today* on a concrete policy, so the defect the Kani witness found is
// reproducible on real HCL, and a fix has to flip the marked assertion on
// purpose (and update `legacy`). See the roadmap's Findings table.

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

/// F6 (a): an explicit ungated deny is overridden on enforcement by a gated
/// grant, and by a share-scoped grant. Capability probes still report deny.
#[test]
fn f6_current_behaviour_a_layered_grant_overrides_an_ungated_deny() {
    let gated = acl_of(&[
        r#"path "secret/data/x" { capabilities = ["deny"] }"#,
        r#"path "secret/data/*" {
             capabilities = ["read"]
             groups = ["g1"]
           }"#,
    ]);
    let mut req = Request { operation: Operation::Read, path: "secret/data/x".into(), ..Default::default() };
    req.asset_groups = vec!["g1".into()];
    assert_eq!(gated.allow_operation(&req, true).unwrap().capabilities_bitmap, Capability::Deny.to_bits());
    // DEFECT: deny should win. Flip to `!allowed` with the F6 fix.
    assert!(gated.allow_operation(&req, false).unwrap().allowed);

    let shared = acl_of(&[
        r#"path "secret/data/x" { capabilities = ["deny"] }"#,
        r#"path "secret/data/*" {
             capabilities = ["read"]
             scopes = ["shared"]
           }"#,
    ]);
    let mut req = Request { operation: Operation::Read, path: "secret/data/x".into(), ..Default::default() };
    let mut auth = Auth::default();
    auth.metadata.insert("entity_id".into(), "u1".into());
    req.auth = Some(auth);
    req.target_shared_caps = vec!["read".into()];
    // DEFECT: a share must not override an administrator's deny.
    assert!(shared.allow_operation(&req, false).unwrap().allowed);
}

/// F6 (b): a gated deny that applies does not wipe a gated grant on
/// enforcement.
#[test]
fn f6_current_behaviour_a_gated_deny_does_not_wipe_on_enforcement() {
    let acl = acl_of(&[
        r#"path "secret/data/*" {
             capabilities = ["read"]
             groups = ["g1"]
           }"#,
        r#"path "secret/data/x" {
             capabilities = ["deny"]
             groups = ["g1"]
           }"#,
    ]);
    let mut req = Request { operation: Operation::Read, path: "secret/data/x".into(), ..Default::default() };
    req.asset_groups = vec!["g1".into()];
    assert_eq!(acl.allow_operation(&req, true).unwrap().capabilities_bitmap, Capability::Deny.to_bits());
    // DEFECT: the gated deny should wipe the grant. Flip with the F6 fix.
    assert!(acl.allow_operation(&req, false).unwrap().allowed);
}

/// F7: an exact rule withholds LIST on `secret/metadata/`; a broader
/// `secret/*` rule (out-specified, so not governing) lists; a gated rule
/// grants a group-filtered LIST. The filter is dropped because the
/// non-governing rule lists, so the LIST is served unfiltered — without the
/// gated rule it is denied.
#[test]
fn f7_current_behaviour_a_non_governing_list_rule_drops_the_filter() {
    let exact_and_prefix =
        [r#"path "secret/metadata/" { capabilities = ["read"] }"#, r#"path "secret/*" { capabilities = ["list"] }"#];
    let req = Request { operation: Operation::List, path: "secret/metadata/".into(), ..Default::default() };
    assert!(!acl_of(&exact_and_prefix).allow_operation(&req, false).unwrap().allowed);

    let with_gated = acl_of(&[
        exact_and_prefix[0],
        exact_and_prefix[1],
        r#"path "secret/metadata/*" {
             capabilities = ["list"]
             groups = ["g1"]
           }"#,
    ]);
    let r = with_gated.allow_operation(&req, false).unwrap();
    assert!(r.allowed);
    // DEFECT: the LIST should keep the `g1` filter. Flip with the F7 fix.
    assert!(r.list_filter_groups.is_empty());
}

/// F8: a gated or scoped segment-wildcard rule with a trailing `*` keeps the
/// `*` as a literal segment and matches no real path (fail-closed), where
/// the same rule ungated is a prefix rule.
#[test]
fn f8_current_behaviour_a_gated_segment_wildcard_glob_matches_nothing() {
    let rule = r#"path "secret/+/data/*" {
             capabilities = ["read"]
             groups = ["g1"]
           }"#;
    let mut req = Request { operation: Operation::Read, path: "secret/x/data/y".into(), ..Default::default() };
    req.asset_groups = vec!["g1".into()];
    // DEFECT (fail-closed): should be allowed. Flip with the F8 fix.
    assert!(!acl_of(&[rule]).allow_operation(&req, false).unwrap().allowed);
    let ungated = r#"path "secret/+/data/*" { capabilities = ["read"] }"#;
    assert!(acl_of(&[ungated]).allow_operation(&req, false).unwrap().allowed);
}
