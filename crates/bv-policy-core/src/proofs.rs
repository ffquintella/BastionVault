//! Kani harnesses for the ACL theorems of
//! `roadmaps/formal-verification-and-type-driven-security.md` § Phase 3
//! (T1–T8), plus two *defect witnesses* (F6, F7).
//!
//! Run: `cargo kani -p bv-policy-core`. Every harness must report
//! `VERIFICATION:- SUCCESSFUL` and every `cover` `SATISFIED`; an
//! `UNSATISFIABLE` cover means the harness's interesting case is unreachable
//! and it proves nothing.
//!
//! **What is quantified over.** The decision functions are generic over the
//! host's index; the harnesses instantiate them with `crate::model`, whose
//! values are *free*: every candidate lookup, every layer rule (path match,
//! gate verdict, filter, permission bitmap, TTLs, parameter facts) and every
//! query is `kani::any()`, constrained only by the well-formedness the host
//! guarantees (`Perm::is_well_formed`, documented at each `assume`). So a
//! harness proves its property for every answer the host's index could give,
//! not for a sample of policies.
//!
//! **Bounds.** Layers hold up to [`MAX_RULES`] rules and paths up to
//! [`MAX_SEGMENTS`] segments. Every harness carries an explicit
//! `#[kani::unwind(5)]` = bound + 1: the longest loop in any harness (a layer
//! scan, a candidate scan, a segment scan, or the 3-entry group / scope
//! universe) runs at most 4 times, and Kani's unwinding assertions — on by
//! default — fail the harness if any loop could run longer.
//!
//! **Defect witnesses.** `f6_*` and `f7_*` state no property: they `cover`
//! a behaviour the code's own comments say cannot happen. `SATISFIED` there
//! means the defect is still present — Kani prints the concrete input. When
//! a fix lands they turn `UNSATISFIABLE`, which fails the gate on purpose:
//! replace each `cover` with the `assert` its doc comment gives.

use core::cmp::Ordering;

use crate::model::*;
use crate::*;

/// A layer of up to `MAX_RULES` rules whose permission sets have the shape
/// the host's parser and merge produce.
fn any_rules() -> Rules {
    let r: Rules = kani::any();
    kani::assume(r.len <= MAX_RULES);
    kani::assume(r.live().iter().all(|x| x.cand.perm.is_well_formed()));
    r
}

/// The three ungated lookups, each well-formed when present.
fn any_index() -> Index {
    let idx: Index = kani::any();
    let ok = |c: &Option<Cand>| c.map_or(true, |c| c.perm.is_well_formed());
    kani::assume(ok(&idx.exact) && ok(&idx.trimmed) && ok(&idx.non_exact));
    idx
}

/// The host's invariant for the layers `ACL::new` builds: a gated rule
/// always carries groups and a scoped rule always carries scopes.
fn assume_filters(r: &Rules) {
    kani::assume(r.live().iter().all(|x| x.has_filter));
}

/// Some rule of `r` is evaluated for this query — its path matches and its
/// gate passes, or the LIST carve-out waives the gate — and satisfies `pred`.
fn applying(r: &Rules, is_list: bool, pred: impl Fn(&Rule) -> bool) -> bool {
    r.live().iter().any(|x| x.matches && (is_list || x.gate) && pred(x))
}

fn denies(c: &Cand) -> bool {
    c.perm.caps & CAP_DENY != 0
}

fn run(q: &Query, idx: &Index, gated: &Rules, scoped: &Rules) -> (Decision, Trace) {
    let mut fx = Trace::default();
    let d = decide(q, idx, gated, scoped, &mut fx);
    (d, fx)
}

// ── T1 — deny supremacy ─────────────────────────────────────────────

/// T1 (capability probes) — a deny that governs the path, or a gated or
/// scoped deny rule that applies, yields exactly `deny`: no `allowed`, no
/// other capability, no LIST filter, no granting policy. This is what
/// `sys/capabilities`, the policy dry-run and `capabilities()` report.
#[kani::proof]
#[kani::unwind(5)]
fn t1_deny_wins_in_capability_probes() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let op: Op = kani::any();
    kani::assume(op != Op::Help);
    let q = Query { acl_is_root: false, op, probe: true };
    let is_list = op == Op::List;

    let gov = governing(is_list, &idx);
    let gov_denies = gov.is_some_and(|c| denies(&c));
    let gated_denies = applying(&gated, is_list, |r| denies(&r.cand));
    let scoped_denies = applying(&scoped, is_list, |r| denies(&r.cand));

    kani::cover!(
        gov_denies && applying(&gated, is_list, |r| r.cand.perm.caps & !CAP_DENY != 0),
        "a governing deny competes with a gated grant"
    );
    kani::cover!(
        !gov_denies && gated_denies && gov.is_some_and(|c| c.perm.caps & CAP_READ != 0),
        "a gated deny competes with an ungated grant"
    );
    kani::cover!(!gov_denies && !gated_denies && scoped_denies, "only a scoped rule denies");

    let (d, fx) = run(&q, &idx, &gated, &scoped);

    if gov_denies || gated_denies || scoped_denies {
        assert!(!d.allowed, "a deny produced a grant");
        assert_eq!(d.caps, CAP_DENY, "deny did not clear the capability bitmap");
        assert!(!d.filtered && !fx.filters_live, "deny left a LIST filter behind");
        assert!(!fx.grants_live, "deny left a granting policy behind");
    }
}

/// T1 (enforcement, ungated rules) — when no gated or scoped rule applies, a
/// governing deny grants nothing: no `allowed`, no capability, no
/// `root_privs`, no granting policy. With `Permissions::merge` keeping deny
/// absorbing (T3), this is deny supremacy among ungated rules: a deny on a
/// path string cannot be merged away, and if it is the most specific rule it
/// decides. (It does not beat a *more specific* grant — that is precedence,
/// T4, and Vault-compatible.)
#[kani::proof]
#[kani::unwind(5)]
fn t1_a_governing_deny_grants_nothing() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let q: Query = kani::any();
    kani::assume(!q.acl_is_root && q.op != Op::Help);
    let is_list = q.op == Op::List;
    kani::assume(!applying(&gated, is_list, |_| true) && !applying(&scoped, is_list, |_| true));

    let gov_denies = governing(is_list, &idx).is_some_and(|c| denies(&c));
    kani::cover!(
        gov_denies && !q.probe && gated.live().iter().any(|r| r.matches),
        "a deny on enforcement, with a matching gated rule whose gate fails"
    );

    let (d, fx) = run(&q, &idx, &gated, &scoped);

    if gov_denies {
        assert!(!d.allowed);
        assert_eq!(d.caps & !CAP_DENY, 0, "a governing deny reported a grantable capability");
        assert!(!d.root_privs);
        assert!(!fx.grants_live);
    }
}

/// F6 — DEFECT WITNESS. On enforcement (`check_only = false`, the mode
/// `PolicyStore::pre_route` uses for every request) an enforcing check of a
/// deny rule reports no capability rather than `deny`, so:
///
/// - (a) a governing ungated deny does not stop the gated/scoped layers, and a
///   gated or scoped grant then allows the request;
/// - (b) a gated or scoped deny rule that applies does not wipe the result.
///
/// The code's comments promise neither can happen. When fixed, replace the
/// covers with:
/// `assert!(!(gov_denies || gated_denies || scoped_denies) || !d.allowed);`
#[kani::proof]
#[kani::unwind(5)]
fn f6_enforcement_lets_a_layered_grant_override_deny() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let op: Op = kani::any();
    kani::assume(op != Op::Help);
    let q = Query { acl_is_root: false, op, probe: false };
    let is_list = op == Op::List;

    let gov_denies = governing(is_list, &idx).is_some_and(|c| denies(&c));
    let layer_denies =
        applying(&gated, is_list, |r| denies(&r.cand)) || applying(&scoped, is_list, |r| denies(&r.cand));

    let (d, _) = run(&q, &idx, &gated, &scoped);

    kani::cover!(gov_denies && d.allowed, "F6a: a gated or scoped grant overrides a governing deny");
    kani::cover!(
        !gov_denies && layer_denies && d.allowed,
        "F6b: an applying gated or scoped deny does not wipe a grant"
    );
}

// ── T2 — fail-closed default ───────────────────────────────────────

/// T2 — with no governing ungated rule and no layered rule that applies, a
/// non-root, non-`help` request is granted nothing and reports nothing: the
/// default is denial, not whatever an earlier step left behind.
#[kani::proof]
#[kani::unwind(5)]
fn t2_no_rule_means_no_grant() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let q: Query = kani::any();
    kani::assume(!q.acl_is_root && q.op != Op::Help);
    let is_list = q.op == Op::List;
    kani::assume(governing(is_list, &idx).is_none());
    kani::assume(!applying(&gated, is_list, |_| true) && !applying(&scoped, is_list, |_| true));

    kani::cover!(
        !is_list && gated.live().iter().any(|r| r.matches && r.cand.perm.caps != 0),
        "a matching gated grant whose gate fails"
    );
    kani::cover!(!is_list && idx.trimmed.is_some(), "a trimmed exact rule that only LIST consults");

    let (d, fx) = run(&q, &idx, &gated, &scoped);

    assert!(!d.allowed);
    assert_eq!(d.caps, 0);
    assert!(!d.root_privs && !d.is_root && !d.filtered);
    assert!(!fx.grants_live && !fx.filters_live);
}

// ── T3 — grant monotonicity ────────────────────────────────────────

/// T3 (merge) — merging two rules with an identical path string keeps deny
/// absorbing in both directions and otherwise never drops a capability: the
/// result is exactly the union.
#[kani::proof]
#[kani::unwind(5)]
fn t3_merge_keeps_deny_and_never_drops_a_capability() {
    let (existing, incoming): (u32, u32) = (kani::any(), kani::any());
    let m = merge_caps(existing, incoming);
    kani::cover!(m == Merge::KeepExisting, "existing deny");
    kani::cover!(m == Merge::Deny, "incoming deny");
    kani::cover!(matches!(m, Merge::Union(c) if c != existing && c != incoming), "a proper union");
    match m {
        Merge::KeepExisting => assert!(existing & CAP_DENY != 0),
        Merge::Deny => assert!(existing & CAP_DENY == 0 && incoming & CAP_DENY != 0),
        Merge::Union(c) => {
            assert!((existing | incoming) & CAP_DENY == 0);
            assert_eq!(c, existing | incoming);
        }
    }
}

/// T3 (layering) — adding one more non-deny gated or scoped rule never
/// revokes `allowed`, `root_privs` or any capability bit, whatever the rest
/// of the ACL is.
#[kani::proof]
#[kani::unwind(5)]
fn t3_an_added_layered_grant_never_removes_a_capability() {
    let (idx, mut gated, mut scoped) = (any_index(), any_rules(), any_rules());
    let q: Query = kani::any();
    let extra: Rule = kani::any();
    kani::assume(extra.cand.perm.is_well_formed() && !denies(&extra.cand));
    let into_gated: bool = kani::any();

    let (before, _) = run(&q, &idx, &gated, &scoped);

    let layer = if into_gated { &mut gated } else { &mut scoped };
    kani::assume(layer.len < MAX_RULES);
    layer.rules[layer.len] = extra;
    layer.len += 1;

    let (after, _) = run(&q, &idx, &gated, &scoped);

    kani::cover!(!before.allowed && after.allowed, "the added rule grants");
    kani::cover!(before.caps != after.caps && before.caps != 0, "the added rule widens an existing grant");

    assert!(!before.allowed || after.allowed, "an added grant revoked `allowed`");
    assert!(!before.root_privs || after.root_privs, "an added grant revoked `root_privs`");
    assert_eq!(after.caps & before.caps, before.caps, "an added grant removed a capability");
}

// ── T4 — specificity precedence and determinism ────────────────────

/// T4 (precedence) — the exact rule governs whenever one exists; for LIST
/// the trimmed exact rule comes next; only then the most specific non-exact
/// rule. One candidate is chosen, never a union.
#[kani::proof]
#[kani::unwind(5)]
fn t4_exact_rules_take_precedence() {
    let idx: Index = kani::any();
    let is_list: bool = kani::any();
    kani::cover!(
        idx.exact.is_some() && idx.non_exact.is_some() && idx.exact != idx.non_exact,
        "exact and non-exact compete"
    );
    kani::cover!(
        is_list && idx.exact.is_none() && idx.trimmed.is_some() && idx.non_exact.is_some(),
        "trimmed exact and non-exact compete"
    );
    let g = governing(is_list, &idx);
    if idx.exact.is_some() {
        assert_eq!(g, idx.exact);
    } else if is_list && idx.trimmed.is_some() {
        assert_eq!(g, idx.trimmed);
    } else {
        assert_eq!(g, idx.non_exact);
    }
}

/// T4 (the order) — `compare` is a strict total order (antisymmetric,
/// transitive, `Equal` only for identical keys), in which a later first
/// wildcard wins and, at the same position, a rule without a trailing `*`
/// beats one with it.
#[kani::proof]
#[kani::unwind(5)]
fn t4_specificity_is_a_strict_total_order() {
    let (a, b, c): (Key, Key, Key) = (kani::any(), kani::any(), kani::any());
    let ab = compare(&a, &b);
    assert_eq!(ab, compare(&b, &a).reverse());
    assert_eq!(ab == Ordering::Equal, a == b);
    if ab != Ordering::Greater && compare(&b, &c) != Ordering::Greater {
        assert!(compare(&a, &c) != Ordering::Greater);
    }
    if a.spec.first_wildcard > b.spec.first_wildcard {
        assert_eq!(ab, Ordering::Greater);
    }
    if a.spec.first_wildcard == b.spec.first_wildcard && !a.spec.is_prefix && b.spec.is_prefix {
        assert_eq!(ab, Ordering::Greater);
    }
    kani::cover!(ab == Ordering::Less && compare(&b, &c) == Ordering::Less, "a strict chain");
}

/// T4 (determinism) — over up to `MAX_RULES` distinct candidates the winner
/// is a maximum, is one of the candidates, and is the same in every offer
/// order, so the verdict does not depend on the segment-wildcard map's
/// iteration order.
#[kani::proof]
#[kani::unwind(5)]
fn t4_the_most_specific_candidate_wins_in_any_order() {
    let keys: [Key; MAX_RULES] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= MAX_RULES);
    for i in 0..n {
        for j in 0..i {
            kani::assume(keys[i] != keys[j]);
        }
    }
    let order: [usize; MAX_RULES] = kani::any();
    for i in 0..n {
        kani::assume(order[i] < n);
        for j in 0..i {
            kani::assume(order[i] != order[j]);
        }
    }

    let mut forward = MostSpecific::new();
    let mut shuffled = MostSpecific::new();
    for i in 0..n {
        forward.offer(keys[i]);
        shuffled.offer(keys[order[i]]);
    }
    let (w, w2) = (forward.into_winner(), shuffled.into_winner());

    kani::cover!(n == MAX_RULES && order[0] != 0, "a full, shuffled candidate set");
    kani::cover!(
        n >= 2 && w != Some(keys[n - 1]) && w != Some(keys[0]),
        "the winner is neither first nor last offered"
    );

    assert_eq!(w, w2, "the winner depends on the offer order");
    assert_eq!(w.is_some(), n > 0);
    if let Some(w) = w {
        assert!(keys[..n].contains(&w));
        for k in keys[..n].iter() {
            assert!(compare(&w, k) != Ordering::Less);
        }
    }
}

/// T4 (path shape) — what a segment-wildcard rule matches, over every rule
/// and path of up to `MAX_SEGMENTS` segments in the abstract alphabet: `+`
/// matches exactly one non-empty segment, a rule without `*` matches only a
/// path of its own length, a prefix rule's last segment is a string prefix,
/// every other segment is equal, and the reported wildcard count (a ranking
/// input) is the number of `+` segments. Sound and complete.
#[kani::proof]
#[kani::unwind(5)]
fn t4_segment_wildcards_match_by_shape() {
    let rule: [Seg; MAX_SEGMENTS] = kani::any();
    let path: [Seg; MAX_SEGMENTS] = kani::any();
    let (rn, pn): (usize, usize) = (kani::any(), kani::any());
    kani::assume((1..=MAX_SEGMENTS).contains(&rn) && (1..=MAX_SEGMENTS).contains(&pn));
    let is_prefix: bool = kani::any();
    let (r, p) = (&rule[..rn], &path[..pn]);

    let m = segments_match(r, is_prefix, p);

    let shape_ok = if is_prefix { pn >= rn } else { pn == rn };
    let segment_ok = |i: usize| {
        if r[i] == Seg::Plus {
            p[i] != Seg::Empty
        } else if is_prefix && i == rn - 1 {
            p[i].starts_with(&r[i])
        } else {
            p[i] == r[i]
        }
    };
    let expected = shape_ok && (0..rn).all(segment_ok);
    assert_eq!(m.is_some(), expected);
    if let Some(w) = m {
        assert_eq!(w, r.iter().filter(|s| **s == Seg::Plus).count());
    }

    kani::cover!(m.is_some_and(|w| w >= 2) && is_prefix && pn > rn, "a two-wildcard prefix rule on a longer path");
    kani::cover!(
        shape_ok && !expected && r.iter().zip(p).any(|(r, p)| *r == Seg::Plus && *p == Seg::Empty),
        "`+` refuses an empty segment"
    );
}

// ── T5 / T6 — gate soundness ───────────────────────────────────────

/// T5 — the group gate: an ungated rule passes; a gated rule passes iff the
/// target is in one of its groups (over a 3-group universe). In the
/// layering: a non-LIST request whose target is outside every gated rule's
/// groups, with no ungated or scoped rule, is granted nothing.
#[kani::proof]
#[kani::unwind(5)]
fn t5_group_gate_is_sound() {
    let target: u8 = kani::any();
    let groups: [u8; MAX_RULES] = kani::any();
    kani::assume(target & !0b111 == 0);
    let mut gated = any_rules();
    for i in 0..MAX_RULES {
        kani::assume(groups[i] & !0b111 == 0);
        let gs = groups[i];
        let passes =
            group_gate_passes((0..3u8).filter(|g| gs & (1u8 << g) != 0), target != 0, |g| target & (1u8 << g) != 0);
        assert_eq!(passes, gs == 0 || gs & target != 0, "group gate");
        gated.rules[i].gate = passes;
    }

    // The roadmap's form: only gated rules, every one carrying groups, none
    // of which contains the target.
    let op: Op = kani::any();
    kani::assume(op != Op::List && op != Op::Help);
    let q = Query { acl_is_root: false, op, probe: kani::any() };
    for i in 0..gated.len {
        kani::assume(groups[i] != 0 && groups[i] & target == 0);
    }
    kani::cover!(
        gated.live().iter().any(|r| r.matches && r.cand.perm.caps & !CAP_DENY != 0),
        "a matching gated grant for a target outside its groups"
    );

    let (d, fx) = run(&q, &Index::default(), &gated, &Rules::default());
    assert!(!d.allowed);
    assert_eq!(d.caps, 0);
    assert!(!d.root_privs && !fx.grants_live);
}

/// T5/T6 — a gated or scoped rule whose gate fails contributes nothing to a
/// non-LIST request: the decision and its payload are identical to the
/// decision with that rule's path not matching at all.
#[kani::proof]
#[kani::unwind(5)]
fn t5_t6_a_failed_gate_contributes_nothing() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let q: Query = kani::any();
    kani::assume(q.op != Op::List);

    let prune = |r: &Rules| {
        let mut out = *r;
        for x in out.rules.iter_mut() {
            if !x.gate {
                x.matches = false;
            }
        }
        out
    };
    let (pg, ps) = (prune(&gated), prune(&scoped));
    kani::cover!(
        gated.live().iter().any(|r| r.matches && !r.gate) && scoped.live().iter().any(|r| r.matches && !r.gate),
        "failed gates in both layers"
    );

    assert_eq!(run(&q, &idx, &gated, &scoped), run(&q, &idx, &pg, &ps));
}

/// T6 — the scope gate, exactly: it passes iff the caller has an entity and
/// a listed scope passes, where `owner` passes for the target's owner (or a
/// write to an unowned target — first write records ownership) and `shared`
/// passes only when the caller's shares include the override capability if
/// one is named, else the capability the operation needs. Unknown scopes
/// never pass.
#[kani::proof]
#[kani::unwind(5)]
fn t6_scope_gate_is_sound() {
    let c: ModelCaller = kani::any();
    kani::assume(c.is_well_formed());
    let scopes: [Scope; 3] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 3);
    let op: Op = kani::any();
    let listed = &scopes[..n];

    let passes = scope_passes(listed.iter().copied(), op, &c);

    let owner_ok = c.owns || (c.unowned && op == Op::Write);
    let shared_ok = c.has_shares
        && match c.share_override {
            Some(granted) => granted,
            None => share_capability(op).is_some_and(|cap| c.shares & share_bit(cap) != 0),
        };
    let expected = c.has_entity
        && ((listed.contains(&Scope::Owner) && owner_ok) || (listed.contains(&Scope::Shared) && shared_ok));
    assert_eq!(passes, expected);

    kani::cover!(passes && !c.owns && c.unowned && op == Op::Write, "first write to an unowned target");
    kani::cover!(
        passes && !listed.contains(&Scope::Owner) && c.share_override.is_none(),
        "a share grants the operation's capability"
    );
    kani::cover!(
        !passes && listed.contains(&Scope::Shared) && c.has_shares && c.has_entity,
        "a share without the needed capability"
    );
    kani::cover!(
        !passes && c.owns && listed.contains(&Scope::Unknown) && !listed.contains(&Scope::Owner),
        "an owner refused by an unknown scope"
    );
}

// ── T5b — the LIST carve-out ───────────────────────────────────────

/// T5b — with only gated and scoped rules (no ungated rule at all), a LIST
/// granted through them always carries a filter, so the post-route pass
/// narrows the keys instead of returning every key.
#[kani::proof]
#[kani::unwind(5)]
fn t5b_gated_list_always_carries_a_filter() {
    let (gated, scoped) = (any_rules(), any_rules());
    assume_filters(&gated);
    assume_filters(&scoped);
    let q = Query { acl_is_root: false, op: Op::List, probe: kani::any() };

    let (d, fx) = run(&q, &Index::default(), &gated, &scoped);

    kani::cover!(d.allowed, "a gated or scoped LIST grant");
    if d.allowed {
        assert!(d.filtered && fx.filters_live, "a gated LIST was granted with no filter");
    }
}

/// T5b (with ungated rules) — a LIST granted with no filter means the
/// governing ungated rule granted it, or some ungated rule the index finds
/// for the path (exact, trimmed exact, or most specific non-exact) carries
/// LIST.
#[kani::proof]
#[kani::unwind(5)]
fn t5b_an_unfiltered_list_needs_an_ungated_list_grant() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    assume_filters(&gated);
    assume_filters(&scoped);
    let q = Query { acl_is_root: false, op: Op::List, probe: kani::any() };

    let gov_grants = governing(true, &idx).is_some_and(|c| check(&c.perm, Op::List, q.probe, &c).allowed);
    let lists = |c: &Option<Cand>| c.is_some_and(|c| c.perm.caps & CAP_LIST != 0);
    let some_ungated_lists = lists(&idx.exact) || lists(&idx.trimmed) || lists(&idx.non_exact);

    let (d, _) = run(&q, &idx, &gated, &scoped);

    kani::cover!(d.allowed && !d.filtered && !gov_grants, "an unfiltered LIST the governing rule did not grant");
    if d.allowed && !d.filtered {
        assert!(gov_grants || some_ungated_lists);
    }
}

/// F7 — DEFECT WITNESS. The filter is dropped when *any* ungated rule the
/// index finds carries LIST, including the most specific non-exact rule when
/// an exact rule that withholds LIST governs. A gated LIST is then served
/// unfiltered on a path where no ungated rule that governs grants LIST. When
/// fixed, replace the cover with:
/// `assert!(!(d.allowed && !d.filtered) || gov_lists);`
#[kani::proof]
#[kani::unwind(5)]
fn f7_a_non_governing_list_rule_drops_the_filter() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    assume_filters(&gated);
    assume_filters(&scoped);
    let q = Query { acl_is_root: false, op: Op::List, probe: false };

    let gov_lists = governing(true, &idx).is_some_and(|c| c.perm.caps & CAP_LIST != 0);
    let (d, _) = run(&q, &idx, &gated, &scoped);

    kani::cover!(
        d.allowed && !d.filtered && !gov_lists,
        "F7: a gated LIST served unfiltered under a governing rule without LIST"
    );
}

// ── T7 — root isolation ────────────────────────────────────────────

/// T7 — only the root ACL yields `is_root`, and it always yields allowed +
/// `root_privs`. A non-root ACL yields `root_privs` only when a permission set
/// that was actually evaluated (the governing rule, or a layered rule that
/// applies) carries `sudo`.
#[kani::proof]
#[kani::unwind(5)]
fn t7_root_isolation() {
    let (idx, gated, scoped) = (any_index(), any_rules(), any_rules());
    let q: Query = kani::any();
    let is_list = q.op == Op::List;

    let (d, _) = run(&q, &idx, &gated, &scoped);

    kani::cover!(
        !q.acl_is_root && d.root_privs && governing(is_list, &idx).is_none(),
        "root_privs from a layered sudo rule"
    );
    if q.acl_is_root {
        assert!(d.allowed && d.is_root && d.root_privs);
    } else {
        assert!(!d.is_root);
        if d.root_privs {
            let sudo = |c: &Cand| c.perm.caps & CAP_SUDO != 0;
            assert!(q.op != Op::Help);
            assert!(
                governing(is_list, &idx).is_some_and(|c| sudo(&c))
                    || applying(&gated, is_list, |r| sudo(&r.cand))
                    || applying(&scoped, is_list, |r| sudo(&r.cand))
            );
        }
    }
}

// ── T8 — parameter constraints ─────────────────────────────────────

/// T8 — on a `read` or `write`: a missing `required_parameters` key refuses;
/// a parameter whose value matches its `denied_parameters` entry, or any
/// parameter at all under a `"*"` deny key, refuses; under a restrictive
/// `allowed_parameters` (not empty, not only `"*"`) a parameter whose value
/// is not allowed, or that is not listed and there is no `"*"` key, refuses.
/// A grant also needs the capability and sane wrapping TTLs, and is complete:
/// with all of that and no violated constraint, the operation is granted.
/// On every other operation the parameters are not consulted at all.
#[kani::proof]
#[kani::unwind(5)]
fn t8_parameter_constraints() {
    let p: KeyedParams = kani::any();
    kani::assume(p.is_well_formed());
    let (caps, min, max): (u32, u128, u128) = (kani::any(), kani::any(), kani::any());
    let perm = p.perm(caps, min, max);
    kani::assume(perm.is_well_formed());
    let op: Op = kani::any();

    let c = check(&perm, op, false, &p);

    if op.checks_parameters() {
        let required_missing = p.required & !p.present & KEYS != 0;
        let denied = p.present != 0 && (p.denied_wildcard || p.present & p.denied & p.denied_match != 0);
        let not_allowed = !perm.allowed_unrestricted()
            && (p.present & p.allowed & !p.allowed_ok != 0
                || (!p.allowed_wildcard && p.present & !p.allowed & KEYS != 0));
        let cap = op.required_capability().unwrap_or(0);
        let has_cap = caps & cap != 0 || (op == Op::Write && caps & CAP_CREATE != 0);

        if required_missing || denied || not_allowed {
            assert!(!c.allowed, "a violated parameter constraint was granted");
        }
        assert_eq!(c.allowed, has_cap && !perm.wrapping_ttl_inverted() && !required_missing && !denied && !not_allowed);
        if c.allowed {
            assert_eq!(c.caps, caps);
        }

        kani::cover!(
            c.allowed && p.present != 0 && !perm.allowed_unrestricted(),
            "granted under a restrictive allow-list"
        );
        kani::cover!(
            !c.allowed && has_cap && !required_missing && !denied && not_allowed,
            "refused by the allow-list alone"
        );
        kani::cover!(
            !c.allowed && has_cap && !required_missing && denied && p.present & p.denied & p.denied_match != 0,
            "refused by a denied value"
        );
    } else {
        let other: KeyedParams = kani::any();
        assert_eq!(c, check(&perm, op, false, &other), "parameters were consulted outside read/write");
        kani::cover!(
            c.allowed && p.required & !p.present & KEYS != 0,
            "a missing required parameter does not refuse a non-read/write op"
        );
    }
}
