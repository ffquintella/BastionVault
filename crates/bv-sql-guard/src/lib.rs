//! SQL statements that cannot be built from runtime data.
//!
//! Parameter binding protects *values*; it cannot bind an identifier (a table
//! name), and a driver call such as hiqlite's `batch` executes several
//! `;`-separated statements. So the only strings allowed to reach a driver are
//! those made here:
//!
//! * a string **literal** (`sql!("SELECT ...")`) — a runtime `String` does not
//!   match the macro's `literal` fragment, so `sql!(user_input)` is a parse
//!   error (checked by the `trybuild` case under `tests/ui`);
//! * a literal with `{}` holes filled by [`SqlIdent`]s, which are validated
//!   against an allow-list at construction;
//! * [`Sql::escape_hatch_reviewed`], deliberately ugly, and every call site must
//!   be recorded in `docs/sql-escape-hatches.md`.
//!
//! [`Sql`] has no `From<String>` and no `Display`-based constructor.

#![forbid(unsafe_code)]

use std::{borrow::Cow, fmt};

/// Longest accepted identifier, in bytes (all accepted bytes are ASCII).
pub const MAX_IDENT_LEN: usize = 63;

/// Why an identifier was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlGuardError {
    Empty,
    BadLeadingChar,
    TooLong,
    IllegalChar,
}

impl fmt::Display for SqlGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "identifier is empty",
            Self::BadLeadingChar => "identifier must start with an ASCII letter or `_`",
            Self::TooLong => "identifier is longer than 63 characters",
            Self::IllegalChar => "identifier may contain only ASCII letters, digits and `_`",
        })
    }
}

impl std::error::Error for SqlGuardError {}

/// A validated SQL identifier (table or column name).
///
/// Accepts `[A-Za-z_][A-Za-z0-9_]{0,62}` and nothing else. Quotes, semicolons,
/// whitespace, comment markers and non-ASCII are *rejected*, not escaped:
/// rejection is checkable by inspection, escaping is dialect-dependent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlIdent(String);

impl SqlIdent {
    pub fn new(raw: &str) -> Result<Self, SqlGuardError> {
        let mut chars = raw.chars();
        match chars.next() {
            None => return Err(SqlGuardError::Empty),
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            Some(_) => return Err(SqlGuardError::BadLeadingChar),
        }
        // `len()` is bytes; a non-ASCII char is rejected below either way.
        if raw.len() > MAX_IDENT_LEN {
            return Err(SqlGuardError::TooLong);
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(SqlGuardError::IllegalChar);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SqlIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A statement safe to hand to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sql(Cow<'static, str>);

impl Sql {
    /// Use through [`sql!`]; the macro is what rejects non-literals.
    pub fn from_literal(lit: &'static str) -> Self {
        Self(Cow::Borrowed(lit))
    }

    /// Fill each `{}` in `lit` with the corresponding identifier.
    ///
    /// Panics if the number of `{}` holes differs from `idents.len()`: both are
    /// fixed at the call site, so this is a programmer error that any test
    /// touching the statement exposes, never something runtime data can cause.
    pub fn from_literal_with_idents(lit: &'static str, idents: &[&SqlIdent]) -> Self {
        let holes = lit.matches("{}").count();
        assert_eq!(
            holes,
            idents.len(),
            "sql!: statement has {holes} `{{}}` hole(s) but {} identifier(s) were supplied",
            idents.len()
        );
        let mut out = String::with_capacity(lit.len() + idents.len() * 16);
        let mut parts = lit.split("{}");
        out.push_str(parts.next().unwrap_or_default());
        for (ident, rest) in idents.iter().zip(parts) {
            out.push_str(ident.as_str());
            out.push_str(rest);
        }
        Self(Cow::Owned(out))
    }

    /// Build a statement from a runtime string.
    ///
    /// Every call must appear in `docs/sql-escape-hatches.md` with a reviewer
    /// and a date. Named to be ugly on purpose: this is the only unproved SQL
    /// in the tree.
    pub fn escape_hatch_reviewed(stmt: String, justification: &'static str) -> Self {
        debug_assert!(!justification.is_empty(), "escape hatch needs a justification");
        Self(Cow::Owned(stmt))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_cow(self) -> Cow<'static, str> {
        self.0
    }
}

/// Build a [`Sql`] from a literal, optionally with `{}` holes filled by
/// `&SqlIdent`s. `sql!(runtime_string)` does not compile.
#[macro_export]
macro_rules! sql {
    ($lit:literal) => {
        $crate::Sql::from_literal($lit)
    };
    ($lit:literal, $($ident:expr),+ $(,)?) => {
        $crate::Sql::from_literal_with_idents($lit, &[$($ident),+])
    };
}

/// Escape a literal key prefix for a `LIKE` pattern used with `ESCAPE '\'`.
///
/// Binding the pattern stops injection but not pattern *widening*: `_` is "any
/// one char" and `%` "any sequence". Escapes both and the escape char itself.
/// A narrowing optimisation, not the authorization boundary — callers must
/// still apply `strip_prefix` to the rows returned (SQLite's `LIKE` is also
/// ASCII-case-insensitive).
pub fn escape_like(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_accepts_plain_identifiers() {
        for good in ["vault", "vault_test", "_v1", "Vault2", &"v".repeat(63)] {
            assert!(SqlIdent::new(good).is_ok(), "{good} should be accepted");
        }
    }

    #[test]
    fn ident_rejects_everything_else() {
        let cases: [(&str, SqlGuardError); 9] = [
            ("", SqlGuardError::Empty),
            ("1vault", SqlGuardError::BadLeadingChar),
            ("vault; DROP TABLE x", SqlGuardError::IllegalChar),
            ("vault\"", SqlGuardError::IllegalChar),
            ("vault--", SqlGuardError::IllegalChar),
            ("vault ", SqlGuardError::IllegalChar),
            ("va`ult", SqlGuardError::IllegalChar),
            ("vаult", SqlGuardError::IllegalChar), // Cyrillic `а` homoglyph
            ("é", SqlGuardError::BadLeadingChar),
        ];
        for (bad, why) in cases {
            assert_eq!(SqlIdent::new(bad), Err(why), "{bad:?}");
        }
        assert_eq!(SqlIdent::new(&"v".repeat(64)), Err(SqlGuardError::TooLong));
    }

    #[test]
    fn sql_substitutes_idents_in_order() {
        let t = SqlIdent::new("vault").unwrap();
        let c = SqlIdent::new("k").unwrap();
        let s = sql!("SELECT {} FROM {} WHERE {} = ?", &c, &t, &c);
        assert_eq!(s.as_str(), "SELECT k FROM vault WHERE k = ?");
        assert_eq!(sql!("SELECT 1").as_str(), "SELECT 1");
    }

    #[test]
    #[should_panic(expected = "hole")]
    fn sql_hole_count_mismatch_panics() {
        let t = SqlIdent::new("vault").unwrap();
        let _ = sql!("SELECT {} FROM {}", &t);
    }

    #[test]
    fn escape_like_neutralizes_wildcards() {
        assert_eq!(escape_like("secret/my_app/"), r"secret/my\_app/");
        assert_eq!(escape_like("secret/my%app/"), r"secret/my\%app/");
        assert_eq!(escape_like(r"secret/a\b"), r"secret/a\\b");
        assert_eq!(escape_like("plain/"), "plain/");
    }

    #[test]
    fn compile_fail_runtime_string() {
        trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
    }
}
