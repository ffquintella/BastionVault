//! One permission set against one operation — `Permissions::check` in the host.

use crate::{Op, CAP_CREATE, CAP_DENY, CAP_SUDO};

/// The facts about one permission set that the verdict depends on. The host
/// builds it from `Permissions` (a single rule, or several rules with an
/// identical path string merged in `ACL::new`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Perm {
    /// The capability bitmap (`CAP_*`).
    pub caps: u32,
    /// `min_wrapping_ttl`, in nanoseconds; `0` means unset.
    pub min_wrapping_ttl_nanos: u128,
    /// `max_wrapping_ttl`, in nanoseconds; `0` means unset.
    pub max_wrapping_ttl_nanos: u128,
    /// `denied_parameters` has a `"*"` key.
    pub denied_wildcard: bool,
    /// Number of keys in `allowed_parameters`, `"*"` included.
    pub allowed_len: usize,
    /// `allowed_parameters` has a `"*"` key.
    pub allowed_wildcard: bool,
}

impl Perm {
    /// Both wrapping TTLs are set and the maximum is below the minimum. Such a
    /// permission grants nothing.
    pub const fn wrapping_ttl_inverted(&self) -> bool {
        self.min_wrapping_ttl_nanos != 0
            && self.max_wrapping_ttl_nanos != 0
            && self.max_wrapping_ttl_nanos < self.min_wrapping_ttl_nanos
    }

    /// `allowed_parameters` restricts nothing: it is empty, or its only key
    /// is `"*"`.
    pub const fn allowed_unrestricted(&self) -> bool {
        self.allowed_len == 0 || (self.allowed_wildcard && self.allowed_len == 1)
    }

    /// The shape the host's parser and merge always produce, and the one the
    /// proofs assume: a bitmap carrying `deny` carries nothing else
    /// (`Policy::init` and `Permissions::merge` both reduce it to exactly
    /// `CAP_DENY`), and a `"*"` key is counted in `allowed_len`.
    pub const fn is_well_formed(&self) -> bool {
        (self.caps & CAP_DENY == 0 || self.caps == CAP_DENY) && (!self.allowed_wildcard || self.allowed_len >= 1)
    }
}

/// What [`check`] needs to know about the request's parameters, relative to
/// one permission set. The host answers these over the request's `data` and
/// `body` maps (case-folded keys, glob-matched values); the proofs answer
/// them from bitsets. Each is consulted at most once, and only when the
/// verdict depends on it.
pub trait Params {
    /// Some `required_parameters` key is absent from both `data` and `body`.
    fn any_required_missing(&self) -> bool;
    /// The request carries no parameters at all (`data` and `body` are both
    /// absent or empty).
    fn is_empty(&self) -> bool;
    /// Some request parameter's key is listed in `denied_parameters` and its
    /// value matches that entry.
    fn any_denied_value(&self) -> bool;
    /// Some request parameter's key is listed in `allowed_parameters` and its
    /// value does not match that entry.
    fn any_listed_value_rejected(&self) -> bool;
    /// Some request parameter's key is not listed in `allowed_parameters`.
    fn any_unlisted(&self) -> bool;
}

/// The outcome of [`check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Check {
    /// The operation is granted by this permission set.
    pub allowed: bool,
    /// The capabilities reported: the full bitmap when granted or probed,
    /// otherwise `0`.
    pub caps: u32,
    /// The permission set carries `sudo`. Set whatever the verdict.
    pub root_privs: bool,
    /// The capability bit whose granting policies the host reports, once the
    /// capability test has passed (whether or not a later test refuses).
    pub granting: Option<u32>,
}

/// Decide `op` against one permission set.
///
/// `probe` is the host's `check_only`: a capability probe (`sys/capabilities`,
/// the policy dry-run) that reports the bitmap without testing an operation,
/// TTLs or parameters, and never reports `allowed`.
///
/// Order of the tests, which is the order the host has always applied them:
/// the capability bit (`Write` is also satisfied by `create`), the wrapping
/// TTLs, then — for `Read` and `Write` only — required parameters, "no
/// parameters at all is allowed", a `"*"` denied key, a denied value, an
/// unrestricted allow-list, and finally an allow-list violation.
pub fn check<P: Params + ?Sized>(perm: &Perm, op: Op, probe: bool, params: &P) -> Check {
    let root_privs = perm.caps & CAP_SUDO != 0;

    if probe {
        return Check { allowed: false, caps: perm.caps, root_privs, granting: None };
    }

    let nothing = Check { allowed: false, caps: 0, root_privs, granting: None };
    let cap = match op.required_capability() {
        Some(cap) => cap,
        None => return nothing,
    };
    if perm.caps & cap == 0 && (op != Op::Write || perm.caps & CAP_CREATE == 0) {
        return nothing;
    }

    let refused = Check { allowed: false, caps: 0, root_privs, granting: Some(cap) };
    let granted = Check { allowed: true, caps: perm.caps, root_privs, granting: Some(cap) };

    if perm.wrapping_ttl_inverted() {
        return refused;
    }

    if op.checks_parameters() {
        if params.any_required_missing() {
            return refused;
        }
        if params.is_empty() {
            return granted;
        }
        if perm.denied_wildcard || params.any_denied_value() {
            return refused;
        }
        if perm.allowed_unrestricted() {
            return granted;
        }
        if params.any_listed_value_rejected() || (!perm.allowed_wildcard && params.any_unlisted()) {
            return refused;
        }
    }

    granted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Facts;
    use crate::{CAP_LIST, CAP_READ, CAP_UPDATE};

    fn perm(caps: u32) -> Perm {
        Perm { caps, ..Perm::default() }
    }

    #[test]
    fn probe_reports_the_bitmap_and_never_allows() {
        let c = check(&perm(CAP_READ | CAP_SUDO), Op::Read, true, &Facts::default());
        assert_eq!(c, Check { allowed: false, caps: CAP_READ | CAP_SUDO, root_privs: true, granting: None });
    }

    #[test]
    fn create_satisfies_write_but_reports_update_as_the_granting_bit() {
        let c = check(&perm(CAP_CREATE), Op::Write, false, &Facts::empty());
        assert!(c.allowed);
        assert_eq!(c.granting, Some(CAP_UPDATE));
        assert!(!check(&perm(CAP_CREATE), Op::Delete, false, &Facts::empty()).allowed);
    }

    #[test]
    fn deny_grants_nothing_on_enforcement() {
        let c = check(&perm(CAP_DENY), Op::Read, false, &Facts::empty());
        assert_eq!(c, Check { allowed: false, caps: 0, root_privs: false, granting: None });
    }

    #[test]
    fn inverted_ttls_refuse_after_the_capability_test() {
        let p = Perm { caps: CAP_READ, min_wrapping_ttl_nanos: 10, max_wrapping_ttl_nanos: 5, ..Perm::default() };
        assert_eq!(check(&p, Op::Read, false, &Facts::empty()).granting, Some(CAP_READ));
        assert!(!check(&p, Op::Read, false, &Facts::empty()).allowed);
    }

    #[test]
    fn parameters_are_ignored_outside_read_and_write() {
        let missing = Facts { required_missing: true, ..Facts::default() };
        assert!(!check(&perm(CAP_READ), Op::Read, false, &missing).allowed);
        assert!(check(&perm(CAP_LIST), Op::List, false, &missing).allowed);
    }

    #[test]
    fn a_request_without_parameters_skips_the_allow_and_deny_lists() {
        let p = Perm { caps: CAP_READ, denied_wildcard: true, allowed_len: 1, ..Perm::default() };
        assert!(check(&p, Op::Read, false, &Facts::empty()).allowed);
        let some = Facts { empty: false, ..Facts::default() };
        assert!(!check(&p, Op::Read, false, &some).allowed);
    }

    #[test]
    fn a_wildcard_allow_key_admits_unlisted_parameters() {
        let p = Perm { caps: CAP_READ, allowed_len: 2, allowed_wildcard: true, ..Perm::default() };
        let unlisted = Facts { empty: false, unlisted: true, ..Facts::default() };
        assert!(check(&p, Op::Read, false, &unlisted).allowed);
        let strict = Perm { allowed_wildcard: false, ..p };
        assert!(!check(&strict, Op::Read, false, &unlisted).allowed);
    }
}
