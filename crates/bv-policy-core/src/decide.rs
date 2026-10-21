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

/// Decide one request.
///
/// 1. A root ACL is allowed everything; `help` is always allowed.
/// 2. The [`governing`] ungated rule is [`check`]ed. If its permission set
///    carries `deny`, the result is `deny` and the decision ends here.
/// 3. Each group-gated rule whose path matches and whose gate passes is
///    checked in turn. A rule whose permission set carries `deny` makes the
///    result `deny` and ends the decision. Otherwise its capabilities are
///    OR'd in, and `allowed` / `root_privs` can only become true. LIST waives
///    the gate and instead marks the grant as filtered.
/// 4. The same for the scope-filtered rules.
/// 5. A filtered LIST becomes unfiltered only when the governing rule's own
///    check reported LIST: its bitmap carries LIST in a capability probe, or
///    it granted the LIST on enforcement.
///
/// "Carries `deny`" is read from the permission set's own bitmap, never from
/// what [`check`] reported: an enforcing check of a deny rule grants nothing
/// and reports no capability, so deciding on its output let a gated or scoped
/// grant override a deny on enforcement (finding F6, closed by T119). The
/// verdict is therefore the same in both modes: a deny that governs or applies
/// is a deny, for a capability probe and for the request itself.
///
/// Only the governing rule can lift the filter. A broader rule the index also
/// finds — the most specific prefix rule when an exact rule governs, or the
/// trimmed exact rule when the untrimmed one does — does not decide the
/// request, so it does not decide whether the response is narrowed either.
/// Consulting every ungated rule served a gated LIST unfiltered on a path
/// whose governing rule withholds LIST (finding F7, closed by T120).
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
    let mut governing_lists = false;

    if let Some(gov) = governing(is_list, ungated) {
        let perm = gov.perm();
        let c = check(&perm, q.op, q.probe, &gov);
        d.allowed = c.allowed;
        d.caps = c.caps;
        d.root_privs = c.root_privs;
        governing_lists = is_list && c.caps & CAP_LIST != 0;
        if let Some(cap) = c.granting {
            fx.grant_base(&gov, cap);
        }
        if perm.caps & CAP_DENY != 0 {
            denied(q, &mut d, fx);
            return d;
        }
    }

    if layer(LayerKind::Gated, gated, q, &mut d, fx) == Flow::Wiped {
        return d;
    }
    if layer(LayerKind::Scoped, scoped, q, &mut d, fx) == Flow::Wiped {
        return d;
    }

    if d.filtered && governing_lists {
        fx.drop_filters();
        d.filtered = false;
    }

    d
}

/// A deny governs the path or a layered deny rule applies: the result is
/// exactly `deny` — not allowed, no other capability, no LIST filter, no
/// granting policy. On enforcement `root_privs` is cleared too, because a
/// caller reads it as a grant (`PolicyStore::readable_targets`). A capability
/// probe keeps the `root_privs` it had already reported, as it always has.
fn denied<C, E: Effects<C>>(q: &Query, d: &mut Decision, fx: &mut E) {
    d.allowed = false;
    d.caps = CAP_DENY;
    d.filtered = false;
    if !q.probe {
        d.root_privs = false;
    }
    fx.wipe();
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
    let is_list = q.op == Op::List;
    for i in 0..l.len() {
        if !l.matches(i) {
            continue;
        }
        if !is_list && !l.gate_passes(i) {
            continue;
        }
        let rule = l.rule(i);
        let perm = rule.perm();
        if perm.caps & CAP_DENY != 0 {
            denied(q, d, fx);
            return Flow::Wiped;
        }
        let c = check(&perm, q.op, q.probe, &rule);
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
    use crate::model::{Cand, Index, Key, Rule, Rules, Trace};
    use crate::{
        merge_caps, Merge, MostSpecific, Specificity, CAP_CONNECT, CAP_READ, CAP_SQL_ADMIN, CAP_SQL_ALTER,
        CAP_SQL_CREATE, CAP_SQL_DELETE, CAP_SQL_DROP, CAP_SQL_EXECUTE, CAP_SQL_EXPORT, CAP_SQL_INSERT, CAP_SQL_SCRIPT,
        CAP_SQL_SELECT, CAP_SQL_UPDATE, CAP_SUDO,
    };

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

    // F7 (T120): only the governing rule lifts the filter.

    #[test]
    fn a_non_governing_list_rule_keeps_the_filter() {
        let gated = Rules::of(&[Rule { matches: true, gate: false, has_filter: true, cand: Cand::caps(CAP_LIST) }]);
        let shadowed = |exact, trimmed| Index { exact, trimmed, non_exact: Some(Cand::caps(CAP_LIST)) };
        for idx in [
            shadowed(Some(Cand::caps(CAP_READ)), None),
            shadowed(None, Some(Cand::caps(CAP_READ))),
            Index { exact: Some(Cand::caps(CAP_READ)), trimmed: Some(Cand::caps(CAP_LIST)), non_exact: None },
        ] {
            for probe in [false, true] {
                let mut fx = Trace::default();
                let d = decide(&q(Op::List, probe), &idx, &gated, &Rules::default(), &mut fx);
                assert!(d.filtered && fx.filters_live && fx.drops == 0, "{idx:?}, probe = {probe}");
                assert_eq!(d.allowed, !probe);
            }
        }
    }

    #[test]
    fn a_governing_rule_that_withholds_the_list_keeps_the_filter() {
        // Carries LIST but grants nothing: inverted wrapping TTLs.
        let mut inverted = Cand::caps(CAP_LIST);
        (inverted.perm.min_wrapping_ttl_nanos, inverted.perm.max_wrapping_ttl_nanos) = (2, 1);
        let gated = Rules::of(&[Rule { matches: true, gate: false, has_filter: true, cand: Cand::caps(CAP_LIST) }]);
        let idx = Index { exact: Some(inverted), ..Index::default() };
        let d = decide(&q(Op::List, false), &idx, &gated, &Rules::default(), &mut Trace::default());
        assert!(d.allowed && d.filtered);
        // A probe reports the bitmap, so the governing rule lists there.
        let d = decide(&q(Op::List, true), &idx, &gated, &Rules::default(), &mut Trace::default());
        assert!(!d.filtered);
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

    // F6 (T119): on enforcement too, a deny is read from the rule's bitmap.

    #[test]
    fn an_enforced_governing_deny_stops_the_layers() {
        let idx = Index { exact: Some(Cand::caps(CAP_DENY)), ..Index::default() };
        let gated = Rules::of(&[Rule { matches: true, gate: true, has_filter: true, cand: Cand::caps(CAP_READ) }]);
        let mut fx = Trace::default();
        let d = decide(&q(Op::Read, false), &idx, &gated, &Rules::default(), &mut fx);
        assert_eq!(d, Decision { allowed: false, root_privs: false, is_root: false, caps: CAP_DENY, filtered: false });
        assert!(!fx.grants_live);
    }

    #[test]
    fn an_enforced_gated_deny_wipes_and_clears_root_privs() {
        let idx = Index { exact: Some(Cand::caps(CAP_READ | CAP_SUDO)), ..Index::default() };
        let gated = Rules::of(&[Rule { matches: true, gate: true, has_filter: true, cand: Cand::caps(CAP_DENY) }]);
        let mut fx = Trace::default();
        let d = decide(&q(Op::Read, false), &idx, &gated, &Rules::default(), &mut fx);
        assert_eq!(d, Decision { allowed: false, root_privs: false, is_root: false, caps: CAP_DENY, filtered: false });
        assert_eq!(fx.wipes, 1);
        assert!(!fx.grants_live);
    }

    // ── SQL capabilities (T124, features/sql-browser.md §3.1) ──────────

    /// A refusal: nothing allowed, no capability reported.
    const REFUSED: Decision = Decision { allowed: false, root_privs: false, is_root: false, caps: 0, filtered: false };
    /// What an applying deny decides ([`denied`]): exactly `deny`.
    const DENIED: Decision = Decision { caps: CAP_DENY, ..REFUSED };

    fn rule_caps(caps: u32) -> Cand {
        Cand::caps(caps)
    }

    /// `rule` is the exact ungated rule for the request path; enforcement.
    fn decide_for(rule: Cand, op: Op) -> Decision {
        let idx = Index { exact: Some(rule), ..Index::default() };
        decide(&q(op, false), &idx, &Rules::default(), &Rules::default(), &mut Trace::default())
    }

    /// Where a test rule sits in the ACL `ACL::new` builds from it.
    #[derive(Clone, Copy, Debug)]
    enum Via {
        /// No `groups` or `scopes`: an exact or prefix rule in the tries.
        Ungated,
        /// `groups = [...]`, with the target in one of them.
        Gated,
        /// `scopes = [...]`, with the caller passing one (owner or share).
        Scoped,
    }

    /// A test rule: its path, its capability bitmap, and where it sits.
    type SqlRule<'a> = (&'a str, u32, Via);

    /// An SQL check of `request`, made as `ACL::explain_capability` makes
    /// one — a READ capability probe, or, with `probe` false, the enforcing
    /// READ — against `rules`, each placed where the host's index finds it.
    /// A path ending in `*` is a prefix rule, any other path an exact one;
    /// among matching ungated prefix rules the most specific governs
    /// ([`crate::compare`]). Segment wildcards are not modelled, and rules
    /// that share a path must be merged first, as `ACL::new` merges them.
    fn decide_sql(rules: &[SqlRule], request: &str, probe: bool) -> (Decision, Trace) {
        let mut idx = Index::default();
        let mut prefixes = MostSpecific::new();
        let (mut gated, mut scoped) = (Rules::default(), Rules::default());
        for (i, &(path, caps, via)) in rules.iter().enumerate() {
            assert!(!path.contains('+'), "segment wildcards are not modelled: {path}");
            let prefix = path.strip_suffix('*');
            let matches = match prefix {
                Some(p) => request.starts_with(p),
                None => path == request,
            };
            match (via, prefix) {
                (Via::Ungated, _) if !matches => {}
                (Via::Ungated, None) => {
                    assert!(idx.exact.is_none(), "merge rules that share a path first");
                    idx.exact = Some(Cand::caps(caps));
                }
                (Via::Ungated, Some(p)) => prefixes.offer(Key {
                    spec: Specificity { first_wildcard: p.len() as isize, is_prefix: true, wildcards: 0, len: p.len() },
                    tie: i as u8,
                }),
                (Via::Gated | Via::Scoped, _) => {
                    let layer = if matches!(via, Via::Gated) { &mut gated } else { &mut scoped };
                    layer.rules[layer.len] = Rule { matches, gate: true, has_filter: true, cand: Cand::caps(caps) };
                    layer.len += 1;
                }
            }
        }
        idx.non_exact = prefixes.into_winner().map(|k: Key| Cand::caps(rules[usize::from(k.tie)].1));
        let mut fx = Trace::default();
        let d = decide(&q(Op::Read, probe), &idx, &gated, &scoped, &mut fx);
        (d, fx)
    }

    const SQL_ROOT: &str = "resources/resources/r/sql/*";
    const SQL_SERVER: &str = "resources/resources/r/sql/server";
    const SQL_OBJECTS: &str = "resources/resources/r/sql/objects/*";
    const SQL_OBJECT: &str = "resources/resources/r/sql/objects/def/s/t";

    /// Every SQL capability, `sql_select` … `sql_script`.
    const SQL_CAPS: [u32; 11] = [
        CAP_SQL_SELECT,
        CAP_SQL_INSERT,
        CAP_SQL_UPDATE,
        CAP_SQL_DELETE,
        CAP_SQL_ALTER,
        CAP_SQL_CREATE,
        CAP_SQL_DROP,
        CAP_SQL_EXECUTE,
        CAP_SQL_ADMIN,
        CAP_SQL_EXPORT,
        CAP_SQL_SCRIPT,
    ];

    /// The eleven bits together: bits 10..=20.
    const ALL_SQL: u32 = (1 << 21) - (1 << 10);

    /// Each SQL bit alone, then all of them at once.
    fn sql_sets() -> impl Iterator<Item = u32> {
        SQL_CAPS.into_iter().chain([ALL_SQL])
    }

    /// Every operation a rule can grant (`Help` consults no rule).
    const PLAIN_OPS: [Op; 7] = [Op::List, Op::Read, Op::Write, Op::Delete, Op::Renew, Op::Revoke, Op::Rollback];

    #[test]
    fn the_sql_bits_are_the_eleven_above_connect() {
        assert!(SQL_CAPS.iter().all(|bit| bit.count_ones() == 1));
        assert_eq!(SQL_CAPS.iter().fold(0, |all, bit| all | bit), ALL_SQL);
        assert_eq!(ALL_SQL.count_ones(), 11);
        assert_eq!(ALL_SQL & ((CAP_CONNECT << 1) - 1), 0);
        for op in PLAIN_OPS {
            assert_eq!(op.required_capability().unwrap() & ALL_SQL, 0, "{op:?}");
        }
    }

    // §3.1 "Nothing implies them", and the converse: they imply nothing.

    #[test]
    fn sql_select_alone_does_not_grant_read() {
        let d = decide_for(rule_caps(CAP_SQL_SELECT), Op::Read);
        assert_eq!(d, REFUSED);
    }

    /// An SQL-only rule grants no operation wherever it sits — governing
    /// exactly, as the most specific prefix rule, or as a group-gated or
    /// scope-filtered rule whose gate passes — and reports no granting
    /// policy or LIST filter. A probe still reports the bits, which is the
    /// only way an SQL capability is ever read (§9.1, probe-only).
    #[test]
    fn no_sql_capability_grants_a_plain_operation() {
        let none = Rules::default();
        for sql in sql_sets() {
            let rule = rule_caps(sql);
            let layered = Rules::of(&[Rule { matches: true, gate: true, has_filter: true, cand: rule }]);
            let placements = [
                (Index { exact: Some(rule), ..Index::default() }, none, none),
                (Index { non_exact: Some(rule), ..Index::default() }, none, none),
                (Index::default(), layered, none),
                (Index::default(), none, layered),
            ];
            for op in PLAIN_OPS {
                for (placement, (idx, gated, scoped)) in placements.iter().enumerate() {
                    let at = alloc::format!("caps = {sql:#x}, {op:?}, placement {placement}");
                    let mut fx = Trace::default();
                    let d = decide(&q(op, false), idx, gated, scoped, &mut fx);
                    assert_eq!(d, REFUSED, "{at}");
                    assert!(!fx.grants_live && !fx.filters_live, "{at}");
                    let d = decide(&q(op, true), idx, gated, scoped, &mut Trace::default());
                    assert_eq!(d, Decision { caps: sql, ..REFUSED }, "probe, {at}");
                }
            }
        }
    }

    /// Adding SQL bits to any combination of the plain capabilities
    /// (`create` … `connect`) never changes whether an operation is
    /// allowed, nor `root_privs` or the LIST filter.
    #[test]
    fn sql_bits_never_change_a_plain_verdict() {
        let mut allowed = 0;
        for plain in 0..(1u32 << 9) {
            let plain = plain << 1; // bits 1..=9; `deny` is never combined (`Perm::is_well_formed`)
            for op in PLAIN_OPS {
                let without = decide_for(rule_caps(plain), op);
                allowed += usize::from(without.allowed);
                for sql in sql_sets() {
                    let with = decide_for(rule_caps(plain | sql), op);
                    assert_eq!(
                        (with.allowed, with.root_privs, with.filtered),
                        (without.allowed, without.root_privs, without.filtered),
                        "plain = {plain:#x}, sql = {sql:#x}, {op:?}"
                    );
                }
            }
        }
        // The sweep met granted and refused verdicts alike.
        assert!(allowed > 0 && allowed < PLAIN_OPS.len() << 9, "allowed = {allowed}");
    }

    // §3.1 "`deny` wins": an applying deny on an SQL path revokes every SQL
    // capability, in a probe (how an SQL check is made) and on enforcement
    // (T119, theorem `t1_deny_wins_on_enforcement`).

    /// A deny applies when it governs the path or sits in a layer whose gate
    /// passes; then it wins over a narrower grant in any other position:
    /// layered grants (asset-group and share rules) are never reached under
    /// a governing deny, and a layered deny wipes a narrower governing grant.
    #[test]
    fn deny_on_sql_path_wins_over_a_narrower_grant() {
        let cases: [(&[SqlRule], &str); 5] = [
            // The deny governs; the grant is narrower, in a layer.
            (&[(SQL_ROOT, CAP_DENY, Via::Ungated), (SQL_OBJECT, ALL_SQL, Via::Gated)], SQL_OBJECT),
            (&[(SQL_ROOT, CAP_DENY, Via::Ungated), (SQL_OBJECT, ALL_SQL, Via::Scoped)], SQL_OBJECT),
            // The deny is layered; the grant is narrower and governs.
            (&[(SQL_ROOT, CAP_DENY, Via::Gated), (SQL_OBJECT, ALL_SQL, Via::Ungated)], SQL_OBJECT),
            (&[(SQL_ROOT, CAP_DENY, Via::Scoped), (SQL_OBJECT, ALL_SQL, Via::Ungated)], SQL_OBJECT),
            // The deny governs a path the narrower grant does not reach.
            (&[(SQL_ROOT, CAP_DENY, Via::Ungated), (SQL_OBJECT, ALL_SQL, Via::Ungated)], SQL_SERVER),
        ];
        for (i, (rules, request)) in cases.into_iter().enumerate() {
            for probe in [true, false] {
                let (d, fx) = decide_sql(rules, request, probe);
                assert_eq!(d, DENIED, "case {i}, probe = {probe}");
                assert!(!fx.grants_live && !fx.filters_live, "case {i}, probe = {probe}");
            }
            // Control: without the deny, the grant is reached where it applies.
            let (control, _) = decide_sql(&rules[1..], request, true);
            assert_eq!(control.caps, if request == SQL_OBJECT { ALL_SQL } else { 0 }, "case {i}, no deny");
        }
    }

    /// Two policies naming the same SQL path: `merge_caps` keeps exactly
    /// `deny`, in either order, and the merged rule decides `deny`.
    #[test]
    fn deny_merged_into_a_sql_path_wins() {
        for sql in sql_sets() {
            for (existing, incoming) in [(sql, CAP_DENY), (CAP_DENY, sql)] {
                let merged = match merge_caps(existing, incoming) {
                    Merge::KeepExisting => existing,
                    Merge::Deny => CAP_DENY,
                    Merge::Union(caps) => caps,
                };
                assert_eq!(merged, CAP_DENY, "{existing:#x} + {incoming:#x}");
                for probe in [true, false] {
                    let (d, _) = decide_sql(&[(SQL_OBJECT, merged, Via::Ungated)], SQL_OBJECT, probe);
                    assert_eq!(d, DENIED, "{existing:#x} + {incoming:#x}, probe = {probe}");
                }
            }
        }
    }

    /// `decide` has no notion of an SQL path: among ungated rules the most
    /// specific governs, here as everywhere (§3.2: "a more specific path
    /// wins over a broader one"; T4). A broader ungated deny therefore does
    /// not reach a narrower ungated grant; it applies only where it governs
    /// (above), or when written at the narrower path or in a layer.
    #[test]
    fn a_narrower_ungated_sql_grant_governs_over_a_broader_ungated_deny() {
        for narrower in [SQL_OBJECT, SQL_OBJECTS] {
            let rules = [(SQL_ROOT, CAP_DENY, Via::Ungated), (narrower, CAP_SQL_SELECT, Via::Ungated)];
            let (d, _) = decide_sql(&rules, SQL_OBJECT, true);
            assert_eq!(d, Decision { caps: CAP_SQL_SELECT, ..REFUSED }, "{narrower}");
            // And on enforcement it grants no plain operation.
            let (d, _) = decide_sql(&rules, SQL_OBJECT, false);
            assert_eq!(d, REFUSED, "{narrower}");
        }
    }
}
