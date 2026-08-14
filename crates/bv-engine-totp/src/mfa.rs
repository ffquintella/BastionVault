//! Shared TOTP second-factor verification.
//!
//! Both the userpass *login* second factor
//! ([`bastion_vault::modules::credential::userpass::path_login`]) and the
//! connect-time *step-up* ceremony
//! ([`bastion_vault::modules::credential::userpass::path_step_up`]) need the same
//! operation: given a principal's bound `(mount, key)` pair and a code the
//! operator just typed, decide whether the code is currently valid.
//!
//! Keeping one implementation here means a change to the skew window, the
//! comparison, or the key lookup applies to every factor check rather than
//! to whichever call site the author happened to be looking at.
//!
//! The engine's `used/` replay index is deliberately *not* consulted — that
//! index belongs to the TOTP engine's own `POST code/:name` contract, and
//! writing into it from an auth backend would couple the two backends'
//! storage layouts. A code is single-use within its period by construction,
//! so the residual replay window is one validity period.

use crate::kernel_api::VaultCtx;
use crate::{errors::RvError, storage::Storage};

use super::{
    crypto::{ct_eq, hotp, step_for},
    policy::KeyPolicy,
};

/// Why a TOTP verification could not even be attempted. Distinct from
/// "the code was wrong" (`Ok(false)`) so callers can tell a
/// misconfiguration apart from a failed factor and report accordingly.
#[derive(Debug)]
pub enum TotpMfaError {
    /// No TOTP engine is mounted at the configured path.
    NoMount(String),
    /// The mount exists but the bound key name is not in it.
    NoKey { mount: String, key: String },
    /// Storage / deserialization failure.
    Storage(RvError),
}

impl std::fmt::Display for TotpMfaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMount(m) => {
                write!(f, "TOTP MFA misconfigured: no secret engine mounted at `{m}`")
            }
            Self::NoKey { mount, key } => {
                write!(f, "TOTP MFA misconfigured: key `{key}` not found in `{mount}`")
            }
            Self::Storage(e) => write!(f, "TOTP MFA storage error: {e}"),
        }
    }
}

impl From<TotpMfaError> for RvError {
    fn from(e: TotpMfaError) -> Self {
        RvError::ErrResponse(e.to_string())
    }
}

/// Normalize a mount path to the trailing-slash form the router matches on.
/// An empty input yields the empty string so callers can fall back to their
/// own default.
pub fn normalize_mount(mount: &str) -> String {
    let m = mount.trim();
    if m.is_empty() {
        String::new()
    } else if m.ends_with('/') {
        m.to_string()
    } else {
        format!("{m}/")
    }
}

/// Verify `code` against the TOTP key `key_name` in the engine mounted at
/// `mount`, honouring the key's own period, digit count, algorithm, and
/// skew window.
///
/// `Ok(true)` = the code is valid right now. `Ok(false)` = it is not.
/// `Err(_)` = the check could not run (no mount, no key, storage failure) —
/// never treat this as a pass.
pub async fn verify_code(
    core: &dyn VaultCtx,
    mount: &str,
    key_name: &str,
    code: &str,
    now_secs: u64,
) -> Result<bool, TotpMfaError> {
    let mount = normalize_mount(mount);
    let view = core
        .router()
        .matching_view(&mount)
        .map_err(TotpMfaError::Storage)?
        .ok_or_else(|| TotpMfaError::NoMount(mount.clone()))?;

    let entry = view
        .get(&format!("key/{key_name}"))
        .await
        .map_err(TotpMfaError::Storage)?
        .ok_or_else(|| TotpMfaError::NoKey { mount: mount.clone(), key: key_name.to_string() })?;

    let policy: KeyPolicy =
        serde_json::from_slice(&entry.value).map_err(|e| TotpMfaError::Storage(e.into()))?;

    Ok(code_matches(&policy, code, now_secs))
}

/// Pure comparison half of [`verify_code`], split out so the skew walk is
/// unit-testable without a live barrier.
///
/// Walks the key's skew window outward from the current step: offset 0
/// first, then ±1, ±2, … up to `policy.skew`. Comparison is constant-time
/// (`ct_eq`) so a wrong code leaks no timing information about how many
/// leading digits were right.
pub fn code_matches(policy: &KeyPolicy, code: &str, now_secs: u64) -> bool {
    let code = code.trim();
    if code.is_empty() {
        return false;
    }
    let centre = step_for(now_secs, policy.period);
    for off in 0..=policy.skew as i64 {
        for sign in if off == 0 { &[0i64][..] } else { &[-1i64, 1][..] } {
            let step = centre as i64 + sign * off;
            if step < 0 {
                continue;
            }
            let expect = hotp(&policy.key, step as u64, policy.algorithm, policy.digits);
            if ct_eq(&expect, code) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::totp;
    use crate::policy::Algorithm;

    fn policy(skew: u32, period: u64) -> KeyPolicy {
        KeyPolicy {
            generate: true,
            key: b"0123456789abcdef0123456789abcdef".to_vec(),
            issuer: "BastionVault".into(),
            account_name: "alice".into(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period,
            skew,
            replay_check: true,
            exported: false,
        }
    }

    #[test]
    fn accepts_the_current_code() {
        let p = policy(1, 30);
        let now = 1_700_000_000u64;
        let code = totp(&p.key, now, p.algorithm, p.digits, p.period);
        assert!(code_matches(&p, &code, now));
    }

    #[test]
    fn accepts_inside_the_skew_window_and_rejects_outside_it() {
        let p = policy(1, 30);
        let now = 1_700_000_000u64;

        // One period back and forward are inside a skew of 1.
        let prev = totp(&p.key, now - 30, p.algorithm, p.digits, p.period);
        let next = totp(&p.key, now + 30, p.algorithm, p.digits, p.period);
        assert!(code_matches(&p, &prev, now));
        assert!(code_matches(&p, &next, now));

        // Two periods out is not.
        let far = totp(&p.key, now + 60, p.algorithm, p.digits, p.period);
        assert!(!code_matches(&p, &far, now));
    }

    #[test]
    fn zero_skew_accepts_only_the_current_step() {
        let p = policy(0, 30);
        let now = 1_700_000_000u64;
        assert!(code_matches(&p, &totp(&p.key, now, p.algorithm, p.digits, p.period), now));
        assert!(!code_matches(&p, &totp(&p.key, now - 30, p.algorithm, p.digits, p.period), now));
    }

    #[test]
    fn rejects_blank_and_wrong_codes() {
        let p = policy(1, 30);
        let now = 1_700_000_000u64;
        assert!(!code_matches(&p, "", now));
        assert!(!code_matches(&p, "   ", now));
        assert!(!code_matches(&p, "000000", now) || {
            // Vanishingly unlikely, but do not let a genuine collision fail CI.
            totp(&p.key, now, p.algorithm, p.digits, p.period) == "000000"
        });
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let p = policy(1, 30);
        let now = 1_700_000_000u64;
        let code = totp(&p.key, now, p.algorithm, p.digits, p.period);
        assert!(code_matches(&p, &format!("  {code} "), now));
    }

    #[test]
    fn mount_normalization() {
        assert_eq!(normalize_mount("totp"), "totp/");
        assert_eq!(normalize_mount("totp/"), "totp/");
        assert_eq!(normalize_mount("  totp-prod  "), "totp-prod/");
        assert_eq!(normalize_mount(""), "");
        assert_eq!(normalize_mount("   "), "");
    }
}
