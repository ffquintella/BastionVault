//! Credentials the host generates for a dynamic role.
//!
//! Generation happens in the host so a plugin cannot hand out a weak
//! credential as if it were strong. Passwords are 24 bytes from the OS random
//! source rendered as URL-safe base64 (32 characters); usernames follow
//! `v-<display>-<role>-<unix>-<8 hex>`. An OS RNG failure is an error, never a
//! fallback to a weaker source.

use std::fmt;

use base64::Engine;
use rand::{rngs::SysRng, TryRng};
use zeroize::Zeroizing;

use crate::{template::sanitize_value, DynamicError};

/// Random bytes behind every generated password.
pub const PASSWORD_BYTES: usize = 24;
/// Length of a generated password: URL-safe base64 of [`PASSWORD_BYTES`].
pub const PASSWORD_LEN: usize = 32;
/// Default ceiling on a generated username (Postgres' NAMEDATALEN - 1).
pub const DEFAULT_USERNAME_MAX_LEN: usize = 63;
/// Shortest ceiling a role may ask for (MySQL 5.7 user names).
pub const MIN_USERNAME_MAX_LEN: usize = 32;
/// Draws before giving up on a password free of `--`; one draw in ~130
/// contains it, so exhausting these means the random source is broken.
const MAX_PASSWORD_DRAWS: usize = 16;

/// A generated password. Wiped on drop; `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedPassword(Zeroizing<String>);

impl GeneratedPassword {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GeneratedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GeneratedPassword(<redacted>)")
    }
}

fn os_fill(buf: &mut [u8]) -> Result<(), DynamicError> {
    SysRng.try_fill_bytes(buf).map_err(|e| DynamicError::Entropy(e.to_string()))
}

/// A random `u64` from the OS random source (a nonce, not a key).
pub fn random_u64() -> Result<u64, DynamicError> {
    let mut buf = [0u8; 8];
    os_fill(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// `bytes` from the OS random source, as lowercase hex (nonces, not keys).
pub fn random_hex(bytes: usize) -> Result<String, DynamicError> {
    let mut buf = vec![0u8; bytes];
    os_fill(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A fresh password from the OS random source.
pub fn generate_password() -> Result<GeneratedPassword, DynamicError> {
    generate_password_with(os_fill)
}

/// [`generate_password`] over an injected byte source, for tests. A draw that
/// contains `--` is discarded (the template renderer refuses it, and in a bare
/// SQL context it would open a comment); the loss of entropy is under 0.02 bit.
pub fn generate_password_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), DynamicError>,
) -> Result<GeneratedPassword, DynamicError> {
    for _ in 0..MAX_PASSWORD_DRAWS {
        let mut raw = Zeroizing::new([0u8; PASSWORD_BYTES]);
        fill(raw.as_mut())?;
        let encoded = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_ref()));
        if !encoded.contains("--") {
            return Ok(GeneratedPassword(encoded));
        }
    }
    Err(DynamicError::Entropy(format!("{MAX_PASSWORD_DRAWS} draws in a row contained `--`")))
}

/// A fresh `v-<display>-<role>-<unix>-<8 hex>` username, at most `max_len`
/// characters (clamped to [`MIN_USERNAME_MAX_LEN`]..=[`DEFAULT_USERNAME_MAX_LEN`]).
pub fn generate_username(display: &str, role: &str, unix_secs: u64, max_len: usize) -> Result<String, DynamicError> {
    let mut suffix = [0u8; 4];
    os_fill(&mut suffix)?;
    Ok(username_from_parts(display, role, unix_secs, suffix, max_len))
}

/// The deterministic half of [`generate_username`]. Display name and role are
/// reduced to `[a-z0-9_]` and share whatever room the fixed parts leave.
pub fn username_from_parts(display: &str, role: &str, unix_secs: u64, suffix: [u8; 4], max_len: usize) -> String {
    let max_len = max_len.clamp(MIN_USERNAME_MAX_LEN, DEFAULT_USERNAME_MAX_LEN);
    let unix = unix_secs.to_string();
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    // "v-" + display + "-" + role + "-" + unix + "-" + hex
    let fixed = 2 + 1 + 1 + unix.len() + 1 + hex.len();
    let budget = max_len.saturating_sub(fixed);
    let display = component(display);
    let role = component(role);
    let display_len = display.len().min(budget / 2).max(1);
    let role_len = role.len().min(budget.saturating_sub(display_len)).max(1);
    let name = format!("v-{}-{}-{unix}-{hex}", &display[..display_len], &role[..role_len]);
    name.chars().take(max_len).collect()
}

/// `[a-z0-9_]`, never empty. ASCII only, so byte slicing is safe.
fn component(raw: &str) -> String {
    let cleaned: String = sanitize_value(&raw.to_ascii_lowercase(), 64)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "none".to_string()
    } else {
        cleaned
    }
}

/// `2026-10-26T18:32:11Z`: what `{{expiration}}` expands to.
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let rem = unix_secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant), valid for every date after 1970.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::template::{render, TemplateVars};

    #[test]
    fn password_is_32_url_safe_characters_from_24_bytes() {
        let p = generate_password().unwrap();
        assert_eq!(p.expose().len(), PASSWORD_LEN);
        assert!(p.expose().chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{}", p.expose());
        assert!(!p.expose().contains("--"));
    }

    #[test]
    fn passwords_do_not_repeat() {
        let seen: HashSet<String> = (0..256).map(|_| generate_password().unwrap().expose().to_string()).collect();
        assert_eq!(seen.len(), 256);
    }

    /// Every one of the 24 bytes reaches the encoding: flipping any input byte
    /// changes the password, so nothing is truncated.
    #[test]
    fn every_random_byte_contributes() {
        let base = generate_password_with(|b| {
            b.fill(0x41);
            Ok(())
        })
        .unwrap();
        for i in 0..PASSWORD_BYTES {
            let p = generate_password_with(|b| {
                b.fill(0x41);
                b[i] ^= 0xff;
                Ok(())
            })
            .unwrap();
            assert_ne!(p, base, "byte {i} did not reach the password");
        }
    }

    #[test]
    fn entropy_failure_is_an_error_not_a_fallback() {
        let err = generate_password_with(|_| Err(DynamicError::Entropy("no entropy".into()))).unwrap_err();
        assert!(matches!(err, DynamicError::Entropy(_)));
        // A source that only ever yields `--` is reported, never accepted.
        let err = generate_password_with(|b| {
            // 0xfb 0xef 0xbe is four 6-bit groups of 62: "----" in base64url.
            b.iter_mut().enumerate().for_each(|(i, x)| *x = [0xfb, 0xef, 0xbe][i % 3]);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, DynamicError::Entropy(_)), "{err:?}");
    }

    #[test]
    fn password_debug_is_redacted() {
        let p = generate_password().unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains(p.expose()));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn username_has_the_vault_compatible_shape() {
        let u = username_from_parts("userpass-Alice", "read-only", 1_793_000_000, [0x0a, 0x1b, 0x2c, 0x3d], 63);
        assert_eq!(u, "v-userpass_alice-read_only-1793000000-0a1b2c3d");
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "v");
        assert_eq!(parts[3], "1793000000");
        assert_eq!(parts[4].len(), 8);
        assert!(parts[4].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn username_fits_the_ceiling_and_keeps_its_suffix() {
        let long = "x".repeat(200);
        for max in [32, 40, 63] {
            let u = username_from_parts(&long, &long, 1_793_000_000, [0xff; 4], max);
            assert!(u.len() <= max, "{u} > {max}");
            assert!(u.ends_with("-1793000000-ffffffff"), "{u}");
        }
        // Out-of-range ceilings are clamped.
        assert!(username_from_parts(&long, &long, 1, [0; 4], 8).len() <= MIN_USERNAME_MAX_LEN);
        assert!(username_from_parts(&long, &long, 1, [0; 4], 500).len() <= DEFAULT_USERNAME_MAX_LEN);
    }

    #[test]
    fn hostile_display_names_cannot_shape_the_username() {
        let u = username_from_parts("x'; DROP TABLE users; --", "", 1, [1, 2, 3, 4], 63);
        assert!(u.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{u}");
        assert!(u.starts_with("v-x___drop_table_users__"), "{u}");
        assert!(u.contains("-none-"), "an empty role is named, not dropped: {u}");
    }

    #[test]
    fn generated_values_always_render() {
        let pw = generate_password().unwrap();
        let name = generate_username("oidc-bob@example.com", "admin", 1_793_000_000, 63).unwrap();
        let exp = rfc3339_utc(1_793_000_000);
        let vars = TemplateVars {
            name: &name,
            password: pw.expose(),
            expiration: &exp,
            role: "admin",
            display_name: "oidc-bob@example.com",
            entity_id: "",
        };
        render("CREATE ROLE \"{{name}}\" PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'", &vars).unwrap();
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_793_000_000), "2026-10-26T07:33:20Z");
        assert_eq!(rfc3339_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }
}
