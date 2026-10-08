//! The decision core of BastionVault's ACL evaluator, small enough to model-check.
//!
//! `bv-kernel`'s `ACL::allow_operation` and `Permissions::check` delegate their
//! verdicts to this crate. What stays in the host is the *index*: the radix
//! tries and the segment-wildcard map that find candidate rules for a path,
//! string normalization, JSON parameter matching, and the asynchronous
//! resolution of asset groups, owners and shares. What lives here is every
//! decision taken over the facts the index produces:
//!
//! - [`check`] — one permission set against one operation: the capability
//!   bit, the wrapping-TTL sanity check, and the order in which
//!   `required_parameters`, `denied_parameters` and `allowed_parameters` are
//!   applied.
//! - [`decide`] — the layering: root and help short-circuits, the governing
//!   ungated rule (exact, then the trailing-slash-trimmed exact rule for LIST,
//!   then the most specific prefix / segment-wildcard rule), then group-gated
//!   rules, then scope-filtered rules, deny wiping the result, the LIST
//!   carve-out and its post-route filter, and dropping that filter when an
//!   ungated rule grants LIST.
//! - [`group_gate_passes`] and [`scope_passes`] — the `groups = [...]` and
//!   `scopes = ["owner" | "shared"]` gates.
//! - [`segments_match`] — how a segment-wildcard rule (`+`) matches a path.
//! - [`compare`] / [`MostSpecific`] — which non-exact rule is the most specific.
//! - [`merge_caps`] — how two rules with an identical path combine.
//!
//! The crate is `no_std`, allocation-free, `unsafe`-free and has no
//! dependencies, so `cargo kani -p bv-policy-core` builds and verifies it in
//! isolation. The harnesses are in `src/proofs.rs` (compiled only under
//! `cfg(kani)`); `docs/verification.md` states what they prove, the bounds,
//! and what is therefore *not* proved.
//!
//! Every generic parameter here is instantiated twice: by the host with real
//! strings and JSON, and by the proofs with the abstract model in
//! `src/model.rs`. The decision code is the same source in both, which is the
//! point: the proofs are statements about the code production runs, not
//! about a hand-written model of it.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod check;
mod decide;
mod gate;
mod merge;
mod path;
mod rank;

#[cfg(any(kani, test))]
pub(crate) mod model;
#[cfg(kani)]
mod proofs;

pub use check::{check, Check, Params, Perm};
pub use decide::{
    decide, governing, ungated_grants_list, Candidate, Decision, Effects, Layer, LayerKind, Query, Ungated,
};
pub use gate::{group_gate_passes, scope_passes, share_capability, Caller, Scope, ShareCap};
pub use merge::{merge_caps, Merge};
pub use path::{segments_match, Segment};
pub use rank::{compare, MostSpecific, Ranked, Specificity};

/// `deny` — wins over every other capability (see [`check`] and [`decide`]
/// for exactly where). Same bit layout as `Capability::to_bits()` in
/// `bv-kernel`; a host test (`capability_bit_layout_matches_core`) asserts it.
pub const CAP_DENY: u32 = 1 << 0;
/// `create`.
pub const CAP_CREATE: u32 = 1 << 1;
/// `read`.
pub const CAP_READ: u32 = 1 << 2;
/// `update`.
pub const CAP_UPDATE: u32 = 1 << 3;
/// `delete`.
pub const CAP_DELETE: u32 = 1 << 4;
/// `list`.
pub const CAP_LIST: u32 = 1 << 5;
/// `sudo` — the capability `root_privs` is derived from.
pub const CAP_SUDO: u32 = 1 << 6;
/// `patch`.
pub const CAP_PATCH: u32 = 1 << 7;
/// `root`.
pub const CAP_ROOT: u32 = 1 << 8;
/// `connect`.
pub const CAP_CONNECT: u32 = 1 << 9;

/// Verification bound, not a production limit: the proofs consider every
/// group-gated layer and every scope-filtered layer of up to this many rules.
/// Production layers are unbounded; see `docs/verification.md` § Limits.
pub const MAX_RULES: usize = 4;

/// Verification bound, not a production limit: the path-shape proofs consider
/// every rule path and request path of up to this many segments.
pub const MAX_SEGMENTS: usize = 4;

/// The request operation, one-to-one with `bv_logical::Operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Op {
    /// `list`
    List,
    /// `read`
    Read,
    /// `write` (create or update)
    Write,
    /// `delete`
    Delete,
    /// `help` — always allowed, never consults a rule.
    Help,
    /// `renew`
    Renew,
    /// `revoke`
    Revoke,
    /// `rollback`
    Rollback,
}

impl Op {
    /// The capability bit an enforcing [`check`] requires for this operation.
    /// `Write` is also satisfied by `create`; `Help` requires nothing and is
    /// never granted by a rule.
    pub const fn required_capability(self) -> Option<u32> {
        match self {
            Op::Read => Some(CAP_READ),
            Op::List => Some(CAP_LIST),
            Op::Write | Op::Renew | Op::Revoke | Op::Rollback => Some(CAP_UPDATE),
            Op::Delete => Some(CAP_DELETE),
            Op::Help => None,
        }
    }

    /// Whether [`check`] applies the parameter constraints to this operation.
    /// Only `Read` and `Write` carry request parameters the constraints are
    /// written for; every other operation ignores them.
    pub const fn checks_parameters(self) -> bool {
        matches!(self, Op::Read | Op::Write)
    }
}
