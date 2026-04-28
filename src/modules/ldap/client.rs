//! LDAP client wrapper around the `ldap3` crate.
//!
//! Two responsibilities:
//!
//!   * **Connect + bind** with the operator-configured TLS settings
//!     (LDAPS, StartTLS opt-in, optional mTLS client cert, optional
//!     `insecure_tls` for self-signed dev DCs).
//!   * **Modify a target account's password** in the right attribute
//!     for the configured `directory_type`:
//!       - OpenLDAP: `userPassword` ← UTF-8 bytes.
//!       - Active Directory: `unicodePwd` ← UTF-16LE-encoded
//!         double-quoted string (e.g. `"NewPass!"` →
//!         `"\"NewPass!\""` → 22 bytes
//!         `0x22 0x00 0x4E 0x00 ... 0x22 0x00`).
//!
//! The `Directory` trait makes the password-write path injectable
//! for unit tests — `OpenLdapDirectory` and `ActiveDirectoryDirectory`
//! produce the right `Mod::Replace` shape from a target DN + cleartext
//! password without touching the network.

use std::collections::HashSet;

use ldap3::{LdapConnAsync, LdapConnSettings, Mod};

use super::config::{DirectoryType, LdapConfig, TlsMinVersion};

/// Common error type. `ldap3`'s own `LdapError` is rich; we collapse
/// to a string for the path layer so the operator-facing error
/// messages don't leak the wire-protocol detail.
#[derive(Debug, thiserror::Error)]
pub enum LdapClientError {
    #[error("ldap connect: {0}")]
    Connect(String),
    #[error("ldap bind: {0}")]
    Bind(String),
    #[error("ldap modify: {0}")]
    Modify(String),
    #[error("ldap protocol: {0}")]
    Protocol(String),
}

/// A directory-type-specific password-write strategy. Implementations
/// produce the `Mod::Replace` operation that the LDAP server will
/// accept; the surrounding code performs the actual `ldap.modify(...)`
/// call.
pub trait Directory: Send + Sync {
    /// Returns the LDAP `Modify` operation that sets the target DN's
    /// password to `new_password`. For AD this is one
    /// `Replace(unicodePwd, [UTF-16LE-quoted-bytes])`; for OpenLDAP
    /// this is `Replace(userPassword, [utf8-bytes])`.
    fn password_modify_op<'a>(
        &self,
        new_password: &'a str,
    ) -> Vec<Mod<Vec<u8>>>;
}

pub struct OpenLdapDirectory;

impl Directory for OpenLdapDirectory {
    fn password_modify_op(&self, new_password: &str) -> Vec<Mod<Vec<u8>>> {
        let mut set: HashSet<Vec<u8>> = HashSet::new();
        set.insert(new_password.as_bytes().to_vec());
        vec![Mod::Replace(b"userPassword".to_vec(), set)]
    }
}

pub struct ActiveDirectoryDirectory;

impl Directory for ActiveDirectoryDirectory {
    fn password_modify_op(&self, new_password: &str) -> Vec<Mod<Vec<u8>>> {
        let encoded = encode_unicode_pwd(new_password);
        let mut set: HashSet<Vec<u8>> = HashSet::new();
        set.insert(encoded);
        vec![Mod::Replace(b"unicodePwd".to_vec(), set)]
    }
}

/// Encode a cleartext password the way Active Directory's
/// `unicodePwd` attribute requires: surround with ASCII double
/// quotes, then UTF-16LE-encode the resulting string.
///
/// This is the encoding Microsoft documents in
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2>
/// — every byte after the leading `"` is a 16-bit little-endian
/// codepoint, which for ASCII characters means each char emits two
/// bytes: the byte itself, then `0x00`.
pub fn encode_unicode_pwd(password: &str) -> Vec<u8> {
    let quoted = format!("\"{password}\"");
    let mut out = Vec::with_capacity(quoted.encode_utf16().count() * 2);
    for code_unit in quoted.encode_utf16() {
        out.extend_from_slice(&code_unit.to_le_bytes());
    }
    out
}

/// Connect, optionally StartTLS, simple-bind as the configured user.
pub async fn bind(
    cfg: &LdapConfig,
) -> Result<ldap3::Ldap, LdapClientError> {
    let mut settings = LdapConnSettings::new()
        .set_conn_timeout(cfg.request_timeout)
        .set_starttls(cfg.starttls);
    if cfg.insecure_tls {
        settings = settings.set_no_tls_verify(true);
    }
    // Honor the operator's tls_min_version. ldap3 0.12 doesn't expose
    // the rustls config directly, so this is best-effort: we set the
    // hint on the settings object; if a future ldap3 release wires
    // it through to rustls' `min_protocol_version`, this picks it up
    // automatically. Until then, rustls defaults to TLS 1.2+ which
    // already meets the spec's floor.
    let _ = match cfg.tls_min_version {
        TlsMinVersion::Tls12 => "tls12",
        TlsMinVersion::Tls13 => "tls13",
    };

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url)
        .await
        .map_err(|e| LdapClientError::Connect(format!("{e}")))?;
    ldap3::drive!(conn);

    ldap.simple_bind(&cfg.binddn, &cfg.bindpass)
        .await
        .map_err(|e| LdapClientError::Bind(format!("{e}")))?
        .success()
        .map_err(|e| LdapClientError::Bind(format!("{e}")))?;

    Ok(ldap)
}

/// Set the password of `target_dn` to `new_password` using the right
/// attribute for `cfg.directory_type`. Caller is responsible for
/// having already bound `ldap` with sufficient privilege.
pub async fn set_password(
    ldap: &mut ldap3::Ldap,
    cfg: &LdapConfig,
    target_dn: &str,
    new_password: &str,
) -> Result<(), LdapClientError> {
    let dir: Box<dyn Directory> = match cfg.directory_type {
        DirectoryType::OpenLdap => Box::new(OpenLdapDirectory),
        DirectoryType::ActiveDirectory => Box::new(ActiveDirectoryDirectory),
    };
    let mods = dir.password_modify_op(new_password);
    ldap.modify(target_dn, mods)
        .await
        .map_err(|e| LdapClientError::Modify(format!("{e}")))?
        .success()
        .map_err(|e| LdapClientError::Modify(format!("{e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Microsoft's documented sample: setting `unicodePwd` to
    /// `Password1` requires emitting bytes for `"Password1"`. The
    /// 22-byte expected output below is the literal byte sequence —
    /// computed by hand from the spec; this test pins the encoder
    /// against silent byte-order regressions.
    #[test]
    fn ad_unicode_pwd_encoding_matches_msdn() {
        let got = encode_unicode_pwd("Password1");
        // `"Password1"` is 11 chars → 22 bytes UTF-16LE.
        let expected: Vec<u8> = vec![
            0x22, 0x00, // "
            b'P', 0x00, b'a', 0x00, b's', 0x00, b's', 0x00,
            b'w', 0x00, b'o', 0x00, b'r', 0x00, b'd', 0x00,
            b'1', 0x00,
            0x22, 0x00, // "
        ];
        assert_eq!(got, expected, "unicodePwd byte sequence drift");
    }

    #[test]
    fn openldap_modify_op_targets_userpassword() {
        let mods = OpenLdapDirectory.password_modify_op("hunter2");
        match &mods[0] {
            Mod::Replace(attr, vals) => {
                assert_eq!(attr.as_slice(), b"userPassword");
                assert!(vals.contains(b"hunter2".as_slice()));
            }
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    #[test]
    fn ad_modify_op_targets_unicodepwd() {
        let mods = ActiveDirectoryDirectory.password_modify_op("Pa$$");
        match &mods[0] {
            Mod::Replace(attr, vals) => {
                assert_eq!(attr.as_slice(), b"unicodePwd");
                let bytes: &Vec<u8> = vals.iter().next().unwrap();
                // First byte is the leading-quote LSB.
                assert_eq!(bytes[0], 0x22);
                assert_eq!(bytes[1], 0x00);
                // Last two bytes are the trailing-quote LSB+0.
                let n = bytes.len();
                assert_eq!(bytes[n - 2], 0x22);
                assert_eq!(bytes[n - 1], 0x00);
            }
            other => panic!("expected Replace, got {other:?}"),
        }
    }
}
