//! Combining the capabilities of two rules with an identical path string.

use crate::CAP_DENY;

/// What `Permissions::merge` does with the capability bitmaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merge {
    /// The existing rule denies: it stays as it is, and nothing of the
    /// incoming rule is kept.
    KeepExisting,
    /// The incoming rule denies: the merged rule is exactly `deny`, and its
    /// parameter allow/deny lists are cleared.
    Deny,
    /// Neither denies: the union, after which the host merges TTLs and
    /// parameter lists.
    Union(u32),
}

/// Merge the capability bitmap of an incoming rule into an existing one.
/// Deny is absorbing in both directions; otherwise capabilities only
/// accumulate.
pub const fn merge_caps(existing: u32, incoming: u32) -> Merge {
    if existing & CAP_DENY != 0 {
        Merge::KeepExisting
    } else if incoming & CAP_DENY != 0 {
        Merge::Deny
    } else {
        Merge::Union(existing | incoming)
    }
}
