//! The two per-rule gates: asset-group membership and ownership scopes.

use crate::Op;

/// Does a group-gated rule's gate pass?
///
/// `rule_groups` are the rule's `groups = [...]`; `target_has_groups` is
/// whether the request target belongs to any asset group at all;
/// `is_member` answers whether the target belongs to one of the rule's groups
/// (the host compares trimmed, lower-cased names). An ungated rule (no groups)
/// passes; a target in no group fails every gated rule; otherwise the rule
/// passes iff the target is in at least one of its groups.
pub fn group_gate_passes<I, F>(rule_groups: I, target_has_groups: bool, is_member: F) -> bool
where
    I: IntoIterator,
    F: FnMut(I::Item) -> bool,
{
    let mut groups = rule_groups.into_iter().peekable();
    if groups.peek().is_none() {
        return true;
    }
    if !target_has_groups {
        return false;
    }
    groups.any(is_member)
}

/// One entry of a rule's `scopes = [...]`, as the host parses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Scope {
    /// `"owner"`: the caller owns the target (or writes an unowned target).
    Owner,
    /// `"shared"`: an active share grants the caller the capability at hand.
    Shared,
    /// Any other value. Never passes, so a typo cannot widen access.
    Unknown,
}

/// The share capability an operation needs, in `SecretShare.capabilities`
/// vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum ShareCap {
    /// `"read"`
    Read,
    /// `"list"`
    List,
    /// `"update"`
    Update,
    /// `"delete"`
    Delete,
}

impl ShareCap {
    /// The capability name as a share records it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ShareCap::Read => "read",
            ShareCap::List => "list",
            ShareCap::Update => "update",
            ShareCap::Delete => "delete",
        }
    }
}

/// The share capability `op` needs. `None` for operations that are not
/// shareable (help, renew, revoke, rollback): a `shared` scope never passes
/// for them.
pub const fn share_capability(op: Op) -> Option<ShareCap> {
    match op {
        Op::Read => Some(ShareCap::Read),
        Op::List => Some(ShareCap::List),
        Op::Write => Some(ShareCap::Update),
        Op::Delete => Some(ShareCap::Delete),
        Op::Help | Op::Renew | Op::Revoke | Op::Rollback => None,
    }
}

/// What the scope gate needs to know about the caller and the target. The
/// host resolves owners and shares in `post_auth`; these answer from them.
pub trait Caller {
    /// The caller has a non-empty `entity_id`.
    fn has_entity(&self) -> bool;
    /// The target has an owner and it is the caller.
    fn owns_target(&self) -> bool;
    /// The target has no owner record.
    fn target_unowned(&self) -> bool;
    /// An active share gives the caller at least one capability on the target.
    fn has_shares(&self) -> bool;
    /// `None` when the request names no `share_capability_override`;
    /// otherwise whether the caller's shares include that capability.
    fn share_override(&self) -> Option<bool>;
    /// The caller's shares include `cap`.
    fn shares(&self, cap: ShareCap) -> bool;
}

/// Does a scope-filtered rule's gate pass? It passes iff the caller has an
/// entity and at least one listed scope passes:
///
/// - [`Scope::Owner`] — the caller owns the target, or the target is unowned
///   and the operation is a `Write` (the first write records ownership).
/// - [`Scope::Shared`] — the caller has shares on the target, and they
///   include the override capability if the request names one, else the
///   capability the operation needs ([`share_capability`]).
/// - [`Scope::Unknown`] — never.
pub fn scope_passes<I, C>(scopes: I, op: Op, caller: &C) -> bool
where
    I: IntoIterator<Item = Scope>,
    C: Caller + ?Sized,
{
    if !caller.has_entity() {
        return false;
    }
    for scope in scopes {
        match scope {
            Scope::Owner => {
                if caller.owns_target() {
                    return true;
                }
                if caller.target_unowned() && op == Op::Write {
                    return true;
                }
            }
            Scope::Shared => {
                if !caller.has_shares() {
                    continue;
                }
                let granted = match caller.share_override() {
                    Some(granted) => granted,
                    None => match share_capability(op) {
                        Some(cap) => caller.shares(cap),
                        None => false,
                    },
                };
                if granted {
                    return true;
                }
            }
            Scope::Unknown => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ModelCaller;

    #[test]
    fn group_gate() {
        let none: [u8; 0] = [];
        assert!(group_gate_passes(none, false, |_| false));
        assert!(!group_gate_passes([1u8], false, |_| true));
        assert!(group_gate_passes([1u8, 2], true, |g| g == 2));
        assert!(!group_gate_passes([1u8, 2], true, |g| g == 3));
    }

    #[test]
    fn owner_scope_admits_a_first_write_only() {
        let unowned = ModelCaller { has_entity: true, unowned: true, ..ModelCaller::default() };
        assert!(scope_passes([Scope::Owner], Op::Write, &unowned));
        assert!(!scope_passes([Scope::Owner], Op::Read, &unowned));
        let anonymous = ModelCaller { has_entity: false, ..unowned };
        assert!(!scope_passes([Scope::Owner], Op::Write, &anonymous));
    }

    #[test]
    fn shared_scope_follows_the_override() {
        let reader = ModelCaller { has_entity: true, has_shares: true, shares: 1 << 0, ..ModelCaller::default() };
        assert!(scope_passes([Scope::Shared], Op::Read, &reader));
        assert!(!scope_passes([Scope::Shared], Op::Delete, &reader));
        let connect = ModelCaller { share_override: Some(false), ..reader };
        assert!(!scope_passes([Scope::Shared], Op::Read, &connect));
        assert!(!scope_passes([Scope::Unknown], Op::Read, &reader));
    }
}
