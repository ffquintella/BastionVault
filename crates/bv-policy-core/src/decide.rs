//! Rule layering — the decision `ACL::allow_operation` reaches for one request.

use crate::check::{check, Params, Perm};
use crate::{Op, CAP_DENY, CAP_LIST};

/// What is being decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Query {
    /// The ACL was built from the `root` policy.
    pub acl_is_root: bool,
    /// The request operation.
    pub op: Op,
    /// A capability probe (the host's `check_only`) rather than an
    /// enforcement decision. See [`check`].
    pub probe: bool,
}

/// The verdict. Payload that has no bearing on it (granting-policy names,
/// filter group and scope names) is reported through [`Effects`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Decision {
    /// The operation is granted.
    pub allowed: bool,
    /// The caller holds `sudo` on the path (or the ACL is root).
    pub root_privs: bool,
    /// The ACL is the root ACL.
    pub is_root: bool,
    /// The capability bitmap reported to the caller.
    pub caps: u32,
    /// A LIST was granted through group-gated or scope-filtered rules, and the
    /// response keys must be narrowed to the filter those rules carry.
    pub filtered: bool,
}

/// A permission set the index found for the request: its facts, and the
/// request's parameters judged against it.
pub trait Candidate: Params {
    /// The permission set's facts.
    fn perm(&self) -> Perm;
}

/// The ungated rules: the host's radix tries and segment-wildcard map. Each
/// lookup is made lazily, at most as often as the original evaluator made it.
pub trait Ungated {
    /// A permission set found by a lookup.
    type Cand: Candidate;
    /// The exact rule for the request path.
    fn exact(&self) -> Option<Self::Cand>;
    /// The exact rule for the request path with its trailing `/` removed.
    /// Consulted for LIST only.
    fn exact_trimmed(&self) -> Option<Self::Cand>;
    /// The most specific prefix or segment-wildcard rule matching the path
    /// (the host selects it with [`crate::MostSpecific`]).
    fn non_exact(&self) -> Option<Self::Cand>;
}

/// One layer of individually evaluated rules: the group-gated rules or the
/// scope-filtered rules, in the order `ACL::new` stored them.
pub trait Layer {
    /// The rule's permission set, as a candidate.
    type Cand: Candidate;
    /// Number of rules in the layer.
    fn len(&self) -> usize;
    /// The layer has no rules.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Rule `i`'s path matches the request path.
    fn matches(&self, i: usize) -> bool;
    /// Rule `i`'s gate passes for this request: the target is in one of its
    /// asset groups ([`crate::group_gate_passes`]) or the caller passes one of
    /// its scopes ([`crate::scope_passes`]). Not consulted for LIST.
    fn gate_passes(&self, i: usize) -> bool;
    /// Rule `i` carries a non-empty filter (its `groups` or `scopes`). Always
    /// true for rules `ACL::new` builds; it is what makes a LIST granted
    /// through the layer a *filtered* LIST.
    fn has_filter(&self, i: usize) -> bool;
    /// Rule `i`'s permission set.
    fn rule(&self, i: usize) -> Self::Cand;
}

/// Which layer an [`Effects`] call is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerKind {
    /// The group-gated rules (`groups = [...]`).
    Gated,
    /// The scope-filtered rules (`scopes = [...]`).
    Scoped,
}

/// The payload half of the result, applied by the host in the order
/// [`decide`] reaches each step: which policies granted, and which filter
/// entries a LIST must be narrowed to.
pub trait Effects<C> {
    /// The governing ungated rule granted through capability bit `cap`: report
    /// its granting policies for that bit.
    fn grant_base(&mut self, governing: &C, cap: u32);
    /// Layer rule `i` granted through `cap`: add its granting policies,
    /// skipping names already reported.
    fn grant_layer(&mut self, kind: LayerKind, i: usize, cap: u32);
    /// Layer rule `i` granted LIST: add its groups (gated) or scopes (scoped)
    /// to the response filter, skipping entries already present.
    fn filter(&mut self, kind: LayerKind, i: usize);
    /// A deny wiped the result: clear the granting policies and both filters.
    fn wipe(&mut self);
    /// An ungated rule also grants LIST: clear both filters.
    fn drop_filters(&mut self);
}

/// The ungated rule that governs the request: the exact rule; for LIST, the
/// exact rule for the path without its trailing `/`; otherwise the most
/// specific prefix or segment-wildcard rule. One winner, never a union.
pub fn governing<U: Ungated>(is_list: bool, ungated: &U) -> Option<U::Cand> {
    if let Some(c) = ungated.exact() {
        return Some(c);
    }
    if is_list {
        if let Some(c) = ungated.exact_trimmed() {
            return Some(c);
        }
    }
    ungated.non_exact()
}

/// Some ungated rule the index finds for the path — the exact rule, the
/// trimmed exact rule, or the most specific non-exact rule — carries LIST.
/// Used to drop a gated/scoped LIST filter.
///
/// Not the same as "the governing rule carries LIST": the non-exact rule is
/// consulted even when an exact rule governs. That is finding F7 in
/// `roadmaps/formal-verification-and-type-driven-security.md`; the
/// `f7_*` harness in `src/proofs.rs` witnesses it.
pub fn ungated_grants_list<U: Ungated>(ungated: &U) -> bool {
    let lists = |c: Option<U::Cand>| c.is_some_and(|c| c.perm().caps & CAP_LIST != 0);
    lists(ungated.exact()) || lists(ungated.exact_trimmed()) || lists(ungated.non_exact())
}

/// Decide one request.
///
/// 1. A root ACL is allowed everything; `help` is always allowed.
/// 2. The [`governing`] ungated rule is [`check`]ed.
/// 3. Unless the result so far carries `deny`, each group-gated rule whose
///    path matches and whose gate passes is checked in turn. A check that
///    reports `deny` wipes the result and ends the decision. Otherwise its
///    capabilities are OR'd in, and `allowed` / `root_privs` can only become
///    true. LIST waives the gate and instead marks the grant as filtered.
/// 4. The same for the scope-filtered rules.
/// 5. A filtered LIST becomes unfiltered when [`ungated_grants_list`].
///
/// A check reports `deny` only in a capability probe: an enforcing check of
/// a deny rule grants nothing and reports no capability, so on enforcement a
/// governing deny does not stop step 3, and a gated or scoped deny does not
/// wipe. That is finding F6; the `f6_*` harness in `src/proofs.rs` witnesses
/// it, and `docs/verification.md` states what deny supremacy is proved for.
pub fn decide<U, G, S, E>(q: &Query, ungated: &U, gated: &G, scoped: &S, fx: &mut E) -> Decision
where
    U: Ungated,
    G: Layer,
    S: Layer,
    E: Effects<U::Cand>,
{
    if q.acl_is_root {
        return Decision { allowed: true, root_privs: true, is_root: true, caps: 0, filtered: false };
    }
    if q.op == Op::Help {
        return Decision { allowed: true, ..Decision::default() };
    }

    let is_list = q.op == Op::List;
    let mut d = Decision::default();

    if let Some(gov) = governing(is_list, ungated) {
        let c = check(&gov.perm(), q.op, q.probe, &gov);
        d.allowed = c.allowed;
        d.caps = c.caps;
        d.root_privs = c.root_privs;
        if let Some(cap) = c.granting {
            fx.grant_base(&gov, cap);
        }
    }

    if layer(LayerKind::Gated, gated, q, &mut d, fx) == Flow::Wiped {
        return d;
    }
    if layer(LayerKind::Scoped, scoped, q, &mut d, fx) == Flow::Wiped {
        return d;
    }

    if is_list && d.filtered && ungated_grants_list(ungated) {
        fx.drop_filters();
        d.filtered = false;
    }

    d
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Wiped,
}

fn layer<L, C, E>(kind: LayerKind, l: &L, q: &Query, d: &mut Decision, fx: &mut E) -> Flow
where
    L: Layer,
    E: Effects<C>,
{
    if d.caps & CAP_DENY != 0 {
        return Flow::Continue;
    }
    let is_list = q.op == Op::List;
    for i in 0..l.len() {
        if !l.matches(i) {
            continue;
        }
        if !is_list && !l.gate_passes(i) {
            continue;
        }
        let rule = l.rule(i);
        let c = check(&rule.perm(), q.op, q.probe, &rule);
        if c.caps & CAP_DENY != 0 {
            d.allowed = false;
            d.caps = CAP_DENY;
            d.filtered = false;
            fx.wipe();
            return Flow::Wiped;
        }
        d.caps |= c.caps;
        d.allowed |= c.allowed;
        d.root_privs |= c.root_privs;
        if let Some(cap) = c.granting {
            fx.grant_layer(kind, i, cap);
        }
        if is_list && c.caps & CAP_LIST != 0 {
            fx.filter(kind, i);
            d.filtered |= l.has_filter(i);
        }
    }
    Flow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cand, Index, Rule, Rules, Trace};
    use crate::{CAP_READ, CAP_SUDO};

    fn q(op: Op, probe: bool) -> Query {
        Query { acl_is_root: false, op, probe }
    }

    #[test]
    fn root_and_help_short_circuit() {
        let none = Index::default();
        let empty = Rules::default();
        let root = Query { acl_is_root: true, ..q(Op::Read, false) };
        let d = decide(&root, &none, &empty, &empty, &mut Trace::default());
        assert!(d.allowed && d.is_root && d.root_privs);
        let d = decide(&q(Op::Help, false), &none, &empty, &empty, &mut Trace::default());
        assert!(d.allowed && !d.is_root && !d.root_privs);
    }

    #[test]
    fn exact_governs_over_non_exact() {
        let idx =
            Index { exact: Some(Cand::caps(CAP_LIST)), non_exact: Some(Cand::caps(CAP_READ)), ..Index::default() };
        let d = decide(&q(Op::Read, false), &idx, &Rules::default(), &Rules::default(), &mut Trace::default());
        assert!(!d.allowed);
    }

    #[test]
    fn gated_list_is_filtered_unless_an_ungated_rule_lists() {
        let gated = Rules::of(&[Rule { matches: true, gate: false, has_filter: true, cand: Cand::caps(CAP_LIST) }]);
        let d = decide(&q(Op::List, false), &Index::default(), &gated, &Rules::default(), &mut Trace::default());
        assert!(d.allowed && d.filtered);
        let idx = Index { non_exact: Some(Cand::caps(CAP_LIST)), ..Index::default() };
        let d = decide(&q(Op::List, false), &idx, &gated, &Rules::default(), &mut Trace::default());
        assert!(d.allowed && !d.filtered);
    }

    #[test]
    fn a_probed_gated_deny_wipes_but_keeps_root_privs() {
        let idx = Index { exact: Some(Cand::caps(CAP_READ | CAP_SUDO)), ..Index::default() };
        let gated = Rules::of(&[Rule { matches: true, gate: true, has_filter: true, cand: Cand::caps(CAP_DENY) }]);
        let mut fx = Trace::default();
        let d = decide(&q(Op::Read, true), &idx, &gated, &Rules::default(), &mut fx);
        assert_eq!(d, Decision { allowed: false, root_privs: true, is_root: false, caps: CAP_DENY, filtered: false });
        assert_eq!(fx.wipes, 1);
    }
}
