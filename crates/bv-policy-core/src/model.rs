//! The abstract instantiation the proofs (and this crate's unit tests) run
//! the decision code against. Compiled only under `cfg(kani)` or `cfg(test)`.
//!
//! Nothing here is a model *of* the decision code — that code is the same
//! generic source the host instantiates. These are the stand-ins for what
//! the host's index supplies: candidate lookups, layer rules, parameter and
//! caller facts, path segments and ranking keys. A proof that quantifies
//! over every value of these types quantifies over every answer the host
//! could give.

// One module serves both the unit tests and the proofs; the items only the
// proofs use (the path alphabet, the scope facts' well-formedness) are dead
// in a `cargo test` build, and the reverse for the test-only constructors.
#![cfg_attr(not(kani), allow(dead_code))]

use crate::check::{Params, Perm};
use crate::decide::{Candidate, Effects, Layer, LayerKind, Ungated};
use crate::gate::{Caller, ShareCap};
use crate::path::Segment;
use crate::rank::{Ranked, Specificity};
use crate::MAX_RULES;

/// Parameter facts as five free booleans — every combination, including
/// ones no real request produces, so a property proved over them holds for
/// whatever the host's JSON matching answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Facts {
    pub required_missing: bool,
    pub empty: bool,
    pub denied_value: bool,
    pub listed_rejected: bool,
    pub unlisted: bool,
}

impl Facts {
    /// A request with no parameters.
    #[cfg(test)]
    pub const fn empty() -> Self {
        Facts { required_missing: false, empty: true, denied_value: false, listed_rejected: false, unlisted: false }
    }
}

impl Params for Facts {
    fn any_required_missing(&self) -> bool {
        self.required_missing
    }
    fn is_empty(&self) -> bool {
        self.empty
    }
    fn any_denied_value(&self) -> bool {
        self.denied_value
    }
    fn any_listed_value_rejected(&self) -> bool {
        self.listed_rejected
    }
    fn any_unlisted(&self) -> bool {
        self.unlisted
    }
}

/// Parameter keys as a 3-bit universe, for stating the parameter theorem in
/// terms of keys and values rather than of answers.
#[cfg(kani)]
pub const KEYS: u8 = 0b111;

/// A request's parameters and one rule's parameter lists over [`KEYS`].
#[cfg(kani)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, kani::Arbitrary)]
pub struct KeyedParams {
    /// Keys the request carries (in `data` or `body`).
    pub present: u8,
    /// `required_parameters`.
    pub required: u8,
    /// Keys listed in `denied_parameters`.
    pub denied: u8,
    /// For a denied key, the request's value matches the deny entry.
    pub denied_match: u8,
    /// Keys listed in `allowed_parameters` (other than `"*"`).
    pub allowed: u8,
    /// For an allowed key, the request's value matches the allow entry.
    pub allowed_ok: u8,
    /// `denied_parameters` has a `"*"` key.
    pub denied_wildcard: bool,
    /// `allowed_parameters` has a `"*"` key.
    pub allowed_wildcard: bool,
}

#[cfg(kani)]
impl KeyedParams {
    pub fn is_well_formed(&self) -> bool {
        (self.present | self.required | self.denied | self.denied_match | self.allowed | self.allowed_ok) & !KEYS == 0
    }

    /// The permission facts these lists imply (`allowed_len` counts `"*"`).
    pub fn perm(&self, caps: u32, min_ttl: u128, max_ttl: u128) -> Perm {
        Perm {
            caps,
            min_wrapping_ttl_nanos: min_ttl,
            max_wrapping_ttl_nanos: max_ttl,
            denied_wildcard: self.denied_wildcard,
            allowed_len: self.allowed.count_ones() as usize + self.allowed_wildcard as usize,
            allowed_wildcard: self.allowed_wildcard,
        }
    }
}

#[cfg(kani)]
impl Params for KeyedParams {
    fn any_required_missing(&self) -> bool {
        self.required & !self.present & KEYS != 0
    }
    fn is_empty(&self) -> bool {
        self.present == 0
    }
    fn any_denied_value(&self) -> bool {
        self.present & self.denied & self.denied_match != 0
    }
    fn any_listed_value_rejected(&self) -> bool {
        self.present & self.allowed & !self.allowed_ok != 0
    }
    fn any_unlisted(&self) -> bool {
        self.present & !self.allowed & KEYS != 0
    }
}

/// A candidate permission set with its parameter facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Cand {
    pub perm: Perm,
    pub params: Facts,
}

impl Cand {
    /// A permission set with only a capability bitmap, against a request
    /// without parameters.
    #[cfg(test)]
    pub fn caps(caps: u32) -> Self {
        Cand { perm: Perm { caps, ..Perm::default() }, params: Facts::empty() }
    }
}

impl Params for Cand {
    fn any_required_missing(&self) -> bool {
        self.params.any_required_missing()
    }
    fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
    fn any_denied_value(&self) -> bool {
        self.params.any_denied_value()
    }
    fn any_listed_value_rejected(&self) -> bool {
        self.params.any_listed_value_rejected()
    }
    fn any_unlisted(&self) -> bool {
        self.params.any_unlisted()
    }
}

impl Candidate for Cand {
    fn perm(&self) -> Perm {
        self.perm
    }
}

/// The three ungated lookups, each answered freely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Index {
    pub exact: Option<Cand>,
    pub trimmed: Option<Cand>,
    pub non_exact: Option<Cand>,
}

impl Ungated for Index {
    type Cand = Cand;
    fn exact(&self) -> Option<Cand> {
        self.exact
    }
    fn exact_trimmed(&self) -> Option<Cand> {
        self.trimmed
    }
    fn non_exact(&self) -> Option<Cand> {
        self.non_exact
    }
}

/// One gated or scoped rule, as the layer reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Rule {
    pub matches: bool,
    pub gate: bool,
    pub has_filter: bool,
    pub cand: Cand,
}

/// A layer of up to [`MAX_RULES`] rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Rules {
    pub len: usize,
    pub rules: [Rule; MAX_RULES],
}

impl Rules {
    #[cfg(test)]
    pub fn of(rules: &[Rule]) -> Self {
        let mut out = Rules::default();
        out.rules[..rules.len()].copy_from_slice(rules);
        out.len = rules.len();
        out
    }

    /// The live rules.
    pub fn live(&self) -> &[Rule] {
        &self.rules[..self.len]
    }
}

impl Layer for Rules {
    type Cand = Cand;
    fn len(&self) -> usize {
        self.len
    }
    fn matches(&self, i: usize) -> bool {
        self.rules[i].matches
    }
    fn gate_passes(&self, i: usize) -> bool {
        self.rules[i].gate
    }
    fn has_filter(&self, i: usize) -> bool {
        self.rules[i].has_filter
    }
    fn rule(&self, i: usize) -> Cand {
        self.rules[i].cand
    }
}

/// What the payload half of the result would hold: whether any granting
/// policy and any filter entry is still reported at the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Trace {
    pub grants_live: bool,
    pub filters_live: bool,
    pub wipes: u8,
    pub drops: u8,
}

impl Effects<Cand> for Trace {
    fn grant_base(&mut self, _governing: &Cand, _cap: u32) {
        self.grants_live = true;
    }
    fn grant_layer(&mut self, _kind: LayerKind, _i: usize, _cap: u32) {
        self.grants_live = true;
    }
    fn filter(&mut self, _kind: LayerKind, _i: usize) {
        self.filters_live = true;
    }
    fn wipe(&mut self) {
        self.grants_live = false;
        self.filters_live = false;
        self.wipes += 1;
    }
    fn drop_filters(&mut self) {
        self.filters_live = false;
        self.drops += 1;
    }
}

/// The caller/target facts for the scope gate. `shares` is a bitset over
/// [`ShareCap`] in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ModelCaller {
    pub has_entity: bool,
    pub owns: bool,
    pub unowned: bool,
    pub has_shares: bool,
    pub share_override: Option<bool>,
    pub shares: u8,
}

pub const fn share_bit(cap: ShareCap) -> u8 {
    match cap {
        ShareCap::Read => 1 << 0,
        ShareCap::List => 1 << 1,
        ShareCap::Update => 1 << 2,
        ShareCap::Delete => 1 << 3,
    }
}

impl ModelCaller {
    /// The combinations the host can produce: owning a target needs a caller
    /// entity and an owner record; holding any share capability (or a
    /// satisfied override) means holding shares.
    #[cfg(kani)]
    pub fn is_well_formed(&self) -> bool {
        (!self.owns || (self.has_entity && !self.unowned))
            && (self.shares == 0 || self.has_shares)
            && (self.share_override != Some(true) || self.has_shares)
            && self.shares & !0b1111 == 0
    }
}

impl Caller for ModelCaller {
    fn has_entity(&self) -> bool {
        self.has_entity
    }
    fn owns_target(&self) -> bool {
        self.owns
    }
    fn target_unowned(&self) -> bool {
        self.unowned
    }
    fn has_shares(&self) -> bool {
        self.has_shares
    }
    fn share_override(&self) -> Option<bool> {
        self.share_override
    }
    fn shares(&self, cap: ShareCap) -> bool {
        self.shares & share_bit(cap) != 0
    }
}

/// The abstract path alphabet. `Empty` is the empty segment (a trailing or
/// doubled `/`); `A` is a proper prefix of `Ab`; `B` is unrelated to both;
/// `Plus` is `+`. Between one rule segment and one path segment — the only
/// comparison [`crate::segments_match`] makes — this realises every
/// combination of the four [`Segment`] predicates that strings can: equal,
/// a proper prefix, unrelated, either side empty, and the wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Seg {
    Empty,
    A,
    Ab,
    B,
    Plus,
}

impl Segment for Seg {
    fn is_wildcard(&self) -> bool {
        *self == Seg::Plus
    }
    fn is_empty(&self) -> bool {
        *self == Seg::Empty
    }
    fn equals(&self, other: &Self) -> bool {
        self == other
    }
    fn starts_with(&self, prefix: &Self) -> bool {
        *prefix == Seg::Empty || self == prefix || (*self == Seg::Ab && *prefix == Seg::A)
    }
}

/// A ranking key with an abstract tie-break.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Key {
    pub spec: Specificity,
    pub tie: u8,
}

impl Ranked for Key {
    type Tiebreak = u8;
    fn specificity(&self) -> Specificity {
        self.spec
    }
    fn tiebreak(&self) -> &u8 {
        &self.tie
    }
}
