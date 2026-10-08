//! The host side of `bv-policy-core`: the ACL's index answering the questions
//! the model-checked decision core asks.
//!
//! `ACL::allow_operation` and `Permissions::check` hand every decision to
//! `bv_policy_core::{decide, check}` (T31 Phase 3.4,
//! `roadmaps/formal-verification-and-type-driven-security.md`). What this
//! module keeps is what the proofs do *not* cover and `docs/verification.md`
//! says so: the trie / segment-wildcard lookups that find candidate rules,
//! case-folded parameter keys and glob-matched JSON values, case-insensitive
//! group names, and the owner / share facts `post_auth` resolved. Each
//! adapter answers one question and decides nothing.
//!
//! The pre-delegation evaluator is frozen in `differential::legacy`; the
//! differential suite there checks this module against it.

use bv_policy_core::{Caller, Candidate, Decision, Effects, Layer, LayerKind, Op, Params, Perm, ShareCap, Ungated};

use super::{
    acl::{
        grouped_rule_matches, rule_gate_passes, scope_passes, scoped_rule_matches, ACLResults, GroupGatedRule,
        ScopedRule, ACL,
    },
    policy::Permissions,
};
use crate::{
    logical::{auth::PolicyInfo, Operation, Request},
    utils::string::GlobContains,
};

/// `Operation` → the core's `Op`. Exhaustive on purpose: a new operation
/// does not compile until someone decides what it requires.
pub(super) fn core_op(op: Operation) -> Op {
    match op {
        Operation::List => Op::List,
        Operation::Read => Op::Read,
        Operation::Write => Op::Write,
        Operation::Delete => Op::Delete,
        Operation::Help => Op::Help,
        Operation::Renew => Op::Renew,
        Operation::Revoke => Op::Revoke,
        Operation::Rollback => Op::Rollback,
    }
}

impl Permissions {
    /// The facts `bv_policy_core::check` decides on.
    pub(super) fn core_facts(&self) -> Perm {
        Perm {
            caps: self.capabilities_bitmap,
            min_wrapping_ttl_nanos: self.min_wrapping_ttl.as_nanos(),
            max_wrapping_ttl_nanos: self.max_wrapping_ttl.as_nanos(),
            denied_wildcard: self.denied_parameters.contains_key("*"),
            allowed_len: self.allowed_parameters.len(),
            allowed_wildcard: self.allowed_parameters.contains_key("*"),
        }
    }
}

/// A request's `data` and `body` judged against one permission set's
/// parameter lists. Keys are compared lower-cased (the lists are stored
/// lower-cased at parse time); values are glob-matched.
pub(super) struct ParamView<'a> {
    pub perm: &'a Permissions,
    pub req: &'a Request,
}

impl Params for ParamView<'_> {
    fn any_required_missing(&self) -> bool {
        self.perm.required_parameters.iter().any(|parameter| {
            let key = parameter.to_lowercase();
            let in_data = self.req.data.as_ref().is_some_and(|data| data.get(key.as_str()).is_some());
            let in_body = self.req.body.as_ref().is_some_and(|body| body.get(key.as_str()).is_some());
            !in_data && !in_body
        })
    }

    fn is_empty(&self) -> bool {
        self.req.data.as_ref().is_none_or(|data| data.is_empty())
            && self.req.body.as_ref().is_none_or(|body| body.is_empty())
    }

    fn any_denied_value(&self) -> bool {
        self.req.data_iter().any(|(key, value)| {
            self.perm
                .denied_parameters
                .get(key.to_lowercase().as_str())
                .is_some_and(|denied| denied.glob_contains(value))
        })
    }

    fn any_listed_value_rejected(&self) -> bool {
        self.req.data_iter().any(|(key, value)| {
            self.perm
                .allowed_parameters
                .get(key.to_lowercase().as_str())
                .is_some_and(|allowed| !allowed.glob_contains(value))
        })
    }

    fn any_unlisted(&self) -> bool {
        self.req.data_iter().any(|(key, _)| !self.perm.allowed_parameters.contains_key(key.to_lowercase().as_str()))
    }
}

/// A permission set found for the request: borrowed from the tries and
/// layers, or the clone the segment-wildcard lookup returns.
pub(super) enum PermSource<'a> {
    Borrowed(&'a Permissions),
    Owned(Permissions),
}

pub(super) struct Cand<'a> {
    perm: PermSource<'a>,
    req: &'a Request,
}

impl<'a> Cand<'a> {
    fn borrowed(perm: &'a Permissions, req: &'a Request) -> Self {
        Cand { perm: PermSource::Borrowed(perm), req }
    }

    fn owned(perm: Permissions, req: &'a Request) -> Self {
        Cand { perm: PermSource::Owned(perm), req }
    }

    fn permissions(&self) -> &Permissions {
        match &self.perm {
            PermSource::Borrowed(perm) => perm,
            PermSource::Owned(perm) => perm,
        }
    }

    fn view(&self) -> ParamView<'_> {
        ParamView { perm: self.permissions(), req: self.req }
    }
}

impl Params for Cand<'_> {
    fn any_required_missing(&self) -> bool {
        self.view().any_required_missing()
    }
    fn is_empty(&self) -> bool {
        self.view().is_empty()
    }
    fn any_denied_value(&self) -> bool {
        self.view().any_denied_value()
    }
    fn any_listed_value_rejected(&self) -> bool {
        self.view().any_listed_value_rejected()
    }
    fn any_unlisted(&self) -> bool {
        self.view().any_unlisted()
    }
}

impl Candidate for Cand<'_> {
    fn perm(&self) -> Perm {
        self.permissions().core_facts()
    }
}

/// The ungated rules: the exact and prefix tries and the segment-wildcard
/// map, looked up for one (leading-slash-free) path.
pub(super) struct UngatedIndex<'a> {
    pub acl: &'a ACL,
    pub path: &'a str,
    pub req: &'a Request,
}

impl<'a> Ungated for UngatedIndex<'a> {
    type Cand = Cand<'a>;

    fn exact(&self) -> Option<Cand<'a>> {
        self.acl.exact_rules.get(self.path).map(|perm| Cand::borrowed(perm, self.req))
    }

    fn exact_trimmed(&self) -> Option<Cand<'a>> {
        self.acl.exact_rules.get(self.path.trim_end_matches('/')).map(|perm| Cand::borrowed(perm, self.req))
    }

    fn non_exact(&self) -> Option<Cand<'a>> {
        self.acl.get_none_exact_paths_permissions(self.path, false).map(|perm| Cand::owned(perm, self.req))
    }
}

/// The group-gated rules, in `ACL::new` order.
pub(super) struct GatedLayer<'a> {
    pub rules: &'a [GroupGatedRule],
    pub path: &'a str,
    pub req: &'a Request,
}

impl<'a> Layer for GatedLayer<'a> {
    type Cand = Cand<'a>;

    fn len(&self) -> usize {
        self.rules.len()
    }
    fn matches(&self, i: usize) -> bool {
        grouped_rule_matches(&self.rules[i], self.path)
    }
    fn gate_passes(&self, i: usize) -> bool {
        rule_gate_passes(&self.rules[i], self.req)
    }
    fn has_filter(&self, i: usize) -> bool {
        !self.rules[i].permissions.groups.is_empty()
    }
    fn rule(&self, i: usize) -> Cand<'a> {
        Cand::borrowed(&self.rules[i].permissions, self.req)
    }
}

/// The scope-filtered rules, in `ACL::new` order.
pub(super) struct ScopedLayer<'a> {
    pub rules: &'a [ScopedRule],
    pub path: &'a str,
    pub req: &'a Request,
}

impl<'a> Layer for ScopedLayer<'a> {
    type Cand = Cand<'a>;

    fn len(&self) -> usize {
        self.rules.len()
    }
    fn matches(&self, i: usize) -> bool {
        scoped_rule_matches(&self.rules[i], self.path)
    }
    fn gate_passes(&self, i: usize) -> bool {
        scope_passes(&self.rules[i], self.req)
    }
    fn has_filter(&self, i: usize) -> bool {
        !self.rules[i].permissions.scopes.is_empty()
    }
    fn rule(&self, i: usize) -> Cand<'a> {
        Cand::borrowed(&self.rules[i].permissions, self.req)
    }
}

/// `scopes = [...]` entries as the core sees them. Scopes are stored
/// lower-cased and trimmed at parse time; anything else never passes.
pub(super) fn parse_scope(scope: &str) -> bv_policy_core::Scope {
    match scope {
        "owner" => bv_policy_core::Scope::Owner,
        "shared" => bv_policy_core::Scope::Shared,
        _ => bv_policy_core::Scope::Unknown,
    }
}

/// The caller and target facts `post_auth` resolved onto the request.
pub(super) struct ScopeCaller<'a> {
    req: &'a Request,
    entity_id: Option<&'a str>,
}

impl<'a> ScopeCaller<'a> {
    pub(super) fn of(req: &'a Request) -> Self {
        let entity_id = req
            .auth
            .as_ref()
            .and_then(|auth| auth.metadata.get("entity_id"))
            .map(String::as_str)
            .filter(|id| !id.is_empty());
        ScopeCaller { req, entity_id }
    }
}

impl Caller for ScopeCaller<'_> {
    fn has_entity(&self) -> bool {
        self.entity_id.is_some()
    }
    fn owns_target(&self) -> bool {
        self.entity_id.is_some_and(|id| !self.req.asset_owner.is_empty() && self.req.asset_owner == id)
    }
    fn target_unowned(&self) -> bool {
        self.req.asset_owner.is_empty()
    }
    fn has_shares(&self) -> bool {
        !self.req.target_shared_caps.is_empty()
    }
    fn share_override(&self) -> Option<bool> {
        self.req.share_capability_override.as_deref().map(|cap| self.req.target_shared_caps.iter().any(|c| c == cap))
    }
    fn shares(&self, cap: ShareCap) -> bool {
        self.req.target_shared_caps.iter().any(|c| c == cap.as_str())
    }
}

/// The payload half of `ACLResults`, built in the order `decide` reports it.
pub(super) struct Payload<'a> {
    acl: &'a ACL,
    granting: Vec<PolicyInfo>,
    groups: Vec<String>,
    scopes: Vec<String>,
}

impl<'a> Payload<'a> {
    pub(super) fn new(acl: &'a ACL) -> Self {
        Payload { acl, granting: Vec::new(), groups: Vec::new(), scopes: Vec::new() }
    }

    fn layer_permissions(acl: &'a ACL, kind: LayerKind, i: usize) -> &'a Permissions {
        match kind {
            LayerKind::Gated => &acl.grouped_rules[i].permissions,
            LayerKind::Scoped => &acl.scoped_rules[i].permissions,
        }
    }

    pub(super) fn into_results(self, d: Decision) -> ACLResults {
        debug_assert_eq!(
            d.filtered,
            !self.groups.is_empty() || !self.scopes.is_empty(),
            "the core's LIST-filter verdict and the filter payload disagree"
        );
        let granting_policies = if d.is_root {
            vec![PolicyInfo {
                name: "root".into(),
                namespace_id: "root".into(),
                policy_type: "acl".into(),
                ..Default::default()
            }]
        } else {
            self.granting
        };
        ACLResults {
            allowed: d.allowed,
            root_privs: d.root_privs,
            is_root: d.is_root,
            capabilities_bitmap: d.caps,
            granting_policies,
            list_filter_groups: self.groups,
            list_filter_scopes: self.scopes,
        }
    }
}

impl<'a> Effects<Cand<'a>> for Payload<'a> {
    fn grant_base(&mut self, governing: &Cand<'a>, cap: u32) {
        if let Some(policies) = governing.permissions().granting_policies_map.get(&cap) {
            self.granting.clone_from(&policies);
        }
    }

    fn grant_layer(&mut self, kind: LayerKind, i: usize, cap: u32) {
        let perm = Self::layer_permissions(self.acl, kind, i);
        if let Some(policies) = perm.granting_policies_map.get(&cap) {
            for policy in policies.iter() {
                if !self.granting.iter().any(|p| p.name == policy.name) {
                    self.granting.push(policy.clone());
                }
            }
        }
    }

    fn filter(&mut self, kind: LayerKind, i: usize) {
        let (entries, into) = match kind {
            LayerKind::Gated => (&self.acl.grouped_rules[i].permissions.groups, &mut self.groups),
            LayerKind::Scoped => (&self.acl.scoped_rules[i].permissions.scopes, &mut self.scopes),
        };
        for entry in entries.iter() {
            if !into.iter().any(|x| x == entry) {
                into.push(entry.clone());
            }
        }
    }

    fn wipe(&mut self) {
        self.granting.clear();
        self.groups.clear();
        self.scopes.clear();
    }

    fn drop_filters(&mut self) {
        self.groups.clear();
        self.scopes.clear();
    }
}
