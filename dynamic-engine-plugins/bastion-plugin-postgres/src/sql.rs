//! SQL the plugin writes itself: quoting and the default statements used
//! when a role leaves its renew or revocation statements empty. Everything
//! else is the operator's statements, rendered by the host.

use bastion_plugin_dynamic_sdk::DynamicError;

/// PostgreSQL's identifier limit (NAMEDATALEN - 1), in bytes.
pub const MAX_IDENT_LEN: usize = 63;

/// `"name"`, with embedded `"` doubled. Refuses what PostgreSQL would
/// truncate or reject (empty, NUL, longer than 63 bytes) instead of letting
/// a revoke drop a different, truncated name.
pub fn quote_ident(name: &str) -> Result<String, DynamicError> {
    if name.is_empty() || name.len() > MAX_IDENT_LEN || name.contains('\0') {
        return Err(DynamicError::invalid(format!("role names must be 1-{MAX_IDENT_LEN} bytes without NUL")));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// `'value'`, with embedded `'` doubled. Backslashes are refused: with
/// `standard_conforming_strings = off` they would escape the closing quote.
pub fn quote_literal(value: &str) -> Result<String, DynamicError> {
    if value.contains('\0') || value.contains('\\') {
        return Err(DynamicError::invalid("SQL literals may not contain NUL or backslash"));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the host's `{{expiration}}` format.
pub fn check_expiration(value: &str) -> Result<(), DynamicError> {
    let b = value.as_bytes();
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let ok = b.len() == 20
        && digits.iter().all(|&i| b[i].is_ascii_digit())
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z';
    if ok {
        Ok(())
    } else {
        Err(DynamicError::Protocol("expiration is not an RFC 3339 UTC timestamp".into()))
    }
}

/// Extend a role's login to `expiration`.
pub fn default_renew(username: &str, expiration: &str) -> Result<String, DynamicError> {
    check_expiration(expiration)?;
    Ok(format!("ALTER ROLE {} VALID UNTIL {}", quote_ident(username)?, quote_literal(expiration)?))
}

/// Drop what the role owns and its privileges in this database, then the
/// role. `IF EXISTS` keeps a repeated revoke from failing.
pub fn default_revocation(username: &str) -> Result<Vec<String>, DynamicError> {
    let ident = quote_ident(username)?;
    Ok(vec![format!("DROP OWNED BY {ident}"), format!("DROP ROLE IF EXISTS {ident}")])
}

/// Set the root role's password.
pub fn alter_password(username: &str, password: &str) -> Result<String, DynamicError> {
    Ok(format!("ALTER ROLE {} WITH PASSWORD {}", quote_ident(username)?, quote_literal(password)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_quoted_and_bounded() {
        assert_eq!(quote_ident("v-root-ro-1-abcd").unwrap(), "\"v-root-ro-1-abcd\"");
        assert_eq!(quote_ident("a\"; DROP TABLE x; --").unwrap(), "\"a\"\"; DROP TABLE x; --\"");
        assert!(quote_ident("").is_err());
        assert!(quote_ident("a\0b").is_err());
        assert!(quote_ident(&"a".repeat(64)).is_err(), "would be truncated to a different name");
        assert!(quote_ident(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn literals_are_quoted_and_refuse_backslashes() {
        assert_eq!(quote_literal("it's").unwrap(), "'it''s'");
        assert!(quote_literal("a\\'; DROP").is_err());
        assert!(quote_literal("a\0").is_err());
    }

    #[test]
    fn default_statements() {
        assert_eq!(
            default_renew("v-u", "2026-10-26T18:32:11Z").unwrap(),
            "ALTER ROLE \"v-u\" VALID UNTIL '2026-10-26T18:32:11Z'"
        );
        assert!(default_renew("v-u", "2026-10-26 18:32:11").is_err());
        assert!(default_renew("v-u", "2026-10-26T18:32:11Z'; DROP ROLE x; --").is_err());
        assert_eq!(default_revocation("v-u").unwrap(), ["DROP OWNED BY \"v-u\"", "DROP ROLE IF EXISTS \"v-u\""]);
        assert_eq!(alter_password("vault", "Ab-c_1").unwrap(), "ALTER ROLE \"vault\" WITH PASSWORD 'Ab-c_1'");
    }
}
