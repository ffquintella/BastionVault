//! The two per-rule gates: asset-group membership and ownership scopes.

use alloc::vec::Vec;

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

/// A share capability, in `SecretShare.capabilities` vocabulary.
///
/// The first four are what an operation needs ([`share_capability`]). The
/// eleven `Sql*` entries are the SQL capabilities of features/sql-browser.md
/// §3.1, named as the policy capability is (`sql_select` …); no operation
/// needs one, so [`share_capability`] never returns them.
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
    /// `"sql_select"`
    SqlSelect,
    /// `"sql_insert"`
    SqlInsert,
    /// `"sql_update"`
    SqlUpdate,
    /// `"sql_delete"`
    SqlDelete,
    /// `"sql_alter"`
    SqlAlter,
    /// `"sql_create"`
    SqlCreate,
    /// `"sql_drop"`
    SqlDrop,
    /// `"sql_execute"`
    SqlExecute,
    /// `"sql_admin"`
    SqlAdmin,
    /// `"sql_export"`
    SqlExport,
    /// `"sql_script"`
    SqlScript,
}

/// Every [`ShareCap`], in declaration order: the vocabulary
/// [`ShareCap::from_names`] accepts.
const SHARE_CAPS: [ShareCap; 15] = [
    ShareCap::Read,
    ShareCap::List,
    ShareCap::Update,
    ShareCap::Delete,
    ShareCap::SqlSelect,
    ShareCap::SqlInsert,
    ShareCap::SqlUpdate,
    ShareCap::SqlDelete,
    ShareCap::SqlAlter,
    ShareCap::SqlCreate,
    ShareCap::SqlDrop,
    ShareCap::SqlExecute,
    ShareCap::SqlAdmin,
    ShareCap::SqlExport,
    ShareCap::SqlScript,
];

impl ShareCap {
    /// The capability name as a share records it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ShareCap::Read => "read",
            ShareCap::List => "list",
            ShareCap::Update => "update",
            ShareCap::Delete => "delete",
            ShareCap::SqlSelect => "sql_select",
            ShareCap::SqlInsert => "sql_insert",
            ShareCap::SqlUpdate => "sql_update",
            ShareCap::SqlDelete => "sql_delete",
            ShareCap::SqlAlter => "sql_alter",
            ShareCap::SqlCreate => "sql_create",
            ShareCap::SqlDrop => "sql_drop",
            ShareCap::SqlExecute => "sql_execute",
            ShareCap::SqlAdmin => "sql_admin",
            ShareCap::SqlExport => "sql_export",
            ShareCap::SqlScript => "sql_script",
        }
    }

    /// The capabilities a share's name list records, in order, duplicates
    /// kept. The inverse of [`ShareCap::to_names`].
    ///
    /// `None` when any name is not exactly the [`ShareCap::as_str`] of a
    /// variant: an unknown, misspelled or differently cased entry refuses
    /// the whole list rather than being dropped, so a typo cannot silently
    /// narrow or widen a share. The share store also accepts `create` and
    /// `connect`, which have no `ShareCap`; a list naming either yields
    /// `None`.
    pub fn from_names(names: &[&str]) -> Option<Vec<ShareCap>> {
        names.iter().map(|name| SHARE_CAPS.iter().copied().find(|cap| cap.as_str() == *name)).collect()
    }

    /// The names a share records for `caps`, in order. The inverse of
    /// [`ShareCap::from_names`].
    pub fn to_names(caps: &[ShareCap]) -> Vec<&'static str> {
        caps.iter().map(|cap| cap.as_str()).collect()
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
    use crate::model::{share_bit, ModelCaller, SHARE_MASK};

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

    #[test]
    fn share_bits_fit_u16_and_keep_existing_values() {
        assert_eq!(share_bit(ShareCap::Read), 1 << 0);
        assert_eq!(share_bit(ShareCap::Delete), 1 << 3);
        let max = [ShareCap::SqlScript].iter().map(|c| share_bit(*c)).max().unwrap();
        assert!(max <= 1 << 14);
    }

    #[test]
    fn existing_share_record_round_trips_unchanged() {
        // fixture: the name list the share store writes today
        let names = ["read", "list", "update", "delete"];
        let caps = ShareCap::from_names(&names).unwrap();
        assert_eq!(ShareCap::to_names(&caps), names.to_vec());
    }

    /// The share bit and the share name of every variant, fixed here rather
    /// than derived: the four pre-T124 entries keep their values and the
    /// eleven SQL entries (features/sql-browser.md §3.1) take bits 4..=14 in
    /// `CAP_SQL_*` order, under the policy capability's own `sql_*` name.
    #[test]
    fn share_caps_have_fixed_bits_and_names() {
        let table: [(ShareCap, u16, &str); 15] = [
            (ShareCap::Read, 1 << 0, "read"),
            (ShareCap::List, 1 << 1, "list"),
            (ShareCap::Update, 1 << 2, "update"),
            (ShareCap::Delete, 1 << 3, "delete"),
            (ShareCap::SqlSelect, 1 << 4, "sql_select"),
            (ShareCap::SqlInsert, 1 << 5, "sql_insert"),
            (ShareCap::SqlUpdate, 1 << 6, "sql_update"),
            (ShareCap::SqlDelete, 1 << 7, "sql_delete"),
            (ShareCap::SqlAlter, 1 << 8, "sql_alter"),
            (ShareCap::SqlCreate, 1 << 9, "sql_create"),
            (ShareCap::SqlDrop, 1 << 10, "sql_drop"),
            (ShareCap::SqlExecute, 1 << 11, "sql_execute"),
            (ShareCap::SqlAdmin, 1 << 12, "sql_admin"),
            (ShareCap::SqlExport, 1 << 13, "sql_export"),
            (ShareCap::SqlScript, 1 << 14, "sql_script"),
        ];
        for (i, (cap, bit, name)) in table.iter().enumerate() {
            assert_eq!(SHARE_CAPS[i], *cap, "SHARE_CAPS is in declaration order");
            assert_eq!(share_bit(*cap), *bit, "{name}");
            assert_eq!(cap.as_str(), *name);
            assert_eq!(ShareCap::from_names(&[*name]), Some([*cap].to_vec()));
        }
        assert_eq!(SHARE_MASK, (1 << 15) - 1, "fifteen distinct bits, nothing above bit 14");
    }

    /// An unknown or differently spelled name is refused as a whole, never
    /// dropped: a caller cannot widen or narrow a share by a typo.
    #[test]
    fn from_names_refuses_unknown_names() {
        assert_eq!(ShareCap::from_names(&["read", "connect"]), None);
        assert_eq!(ShareCap::from_names(&["sqlselect"]), None);
        assert_eq!(ShareCap::from_names(&["READ"]), None);
        assert_eq!(ShareCap::from_names(&[]), Some([].to_vec()));
    }

    /// No request operation needs an SQL share capability, so an SQL-only
    /// share never passes a `shared` scope unless the request names the
    /// capability as its override.
    #[test]
    fn sql_only_shares_grant_no_operation() {
        let sql_only =
            ModelCaller { has_entity: true, has_shares: true, shares: SHARE_MASK & !0b1111, ..ModelCaller::default() };
        for op in [Op::List, Op::Read, Op::Write, Op::Delete, Op::Help, Op::Renew, Op::Revoke, Op::Rollback] {
            assert!(!scope_passes([Scope::Shared], op, &sql_only), "{op:?}");
        }
    }
}
