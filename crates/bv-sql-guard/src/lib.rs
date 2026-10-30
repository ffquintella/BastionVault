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

    /// `"name"`: the identifier quoted for PostgreSQL and standard SQL, so
    /// its case is kept. Nothing needs escaping: the allow-list excludes `"`.
    pub fn double_quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }

    /// `` `name` ``: the identifier quoted for MySQL and MariaDB, read the
    /// same under every `sql_mode` (`ANSI_QUOTES` changes `"`, not the
    /// backtick). Nothing needs escaping: the allow-list excludes `` ` ``.
    pub fn backticked(&self) -> String {
        format!("`{}`", self.0)
    }

    /// `[name]`: the identifier quoted for SQL Server, read the same whether
    /// `QUOTED_IDENTIFIER` is on or off (it changes `"`, not brackets).
    /// Nothing needs escaping: the allow-list excludes `[` and `]`, so the
    /// T-SQL escape (`]` doubled as `]]`) can never be needed here.
    pub fn bracketed(&self) -> String {
        format!("[{}]", self.0)
    }

    /// `"NAME"`: the identifier quoted for Oracle, case kept, so it matches
    /// the data dictionary exactly (pass the name as the dictionary spells
    /// it, usually upper case). Oracle has no escape for a `"` inside a
    /// quoted name at all; the allow-list excludes `"`, so a name that
    /// would need one is refused, never escaped.
    pub fn oracle_quoted(&self) -> String {
        format!("\"{}\"", self.0)
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
    fn quoting_styles_wrap_the_validated_name_only() {
        let id = SqlIdent::new("Users_2").unwrap();
        assert_eq!(id.double_quoted(), "\"Users_2\"");
        assert_eq!(id.backticked(), "`Users_2`");
        // A quote of either style can never be inside: the allow-list
        // refuses it, so quoting needs no escaping.
        for bad in ["a`b", "a\"b", "a``b"] {
            assert!(SqlIdent::new(bad).is_err(), "{bad:?}");
        }
    }

    /// SQL Server brackets: a `]` inside the name would end the identifier
    /// early unless doubled (`]]`). The allow-list refuses both brackets, so
    /// `bracketed` never has to escape, and a name that would need it never
    /// becomes an identifier at all.
    #[test]
    fn bracketed_never_needs_the_close_bracket_escape() {
        let id = SqlIdent::new("Users_2").unwrap();
        assert_eq!(id.bracketed(), "[Users_2]");
        for (bad, why) in [
            ("a]b", SqlGuardError::IllegalChar),
            ("a]]b", SqlGuardError::IllegalChar),
            ("a[b", SqlGuardError::IllegalChar),
            ("a];DROP TABLE t;--", SqlGuardError::IllegalChar),
            ("[a]", SqlGuardError::BadLeadingChar),
            ("]", SqlGuardError::BadLeadingChar),
        ] {
            assert_eq!(SqlIdent::new(bad).map(|i| i.bracketed()), Err(why), "{bad:?}");
        }
        // Whatever `bracketed` returns holds exactly one `[` and one `]`,
        // at the ends: the name cannot close the identifier early.
        for good in ["a", "_x9", &"v".repeat(63)] {
            let q = SqlIdent::new(good).unwrap().bracketed();
            assert!(q.starts_with('[') && q.ends_with(']'));
            assert_eq!(q.matches(']').count(), 1, "{q}");
            assert_eq!(q.matches('[').count(), 1, "{q}");
        }
    }

    /// Oracle quoted names: no escape for `"` exists, so the allow-list must
    /// keep `"` out, and `oracle_quoted` never has anything to escape.
    #[test]
    fn oracle_quoted_keeps_case_and_never_needs_an_escape() {
        assert_eq!(SqlIdent::new("EMPLOYEES").unwrap().oracle_quoted(), "\"EMPLOYEES\"");
        // Case is kept: `"Emp"` and `"EMP"` are different Oracle objects.
        assert_eq!(SqlIdent::new("Emp_2").unwrap().oracle_quoted(), "\"Emp_2\"");
        for (bad, why) in [
            ("a\"b", SqlGuardError::IllegalChar),
            ("a\"\"b", SqlGuardError::IllegalChar),
            ("A\";DROP TABLE T;--", SqlGuardError::IllegalChar),
            ("\"A\"", SqlGuardError::BadLeadingChar),
        ] {
            assert_eq!(SqlIdent::new(bad).map(|i| i.oracle_quoted()), Err(why), "{bad:?}");
        }
        for good in ["A", "_X9", &"V".repeat(63)] {
            let q = SqlIdent::new(good).unwrap().oracle_quoted();
            assert!(q.starts_with('"') && q.ends_with('"'));
            assert_eq!(q.matches('"').count(), 2, "{q}");
        }
    }

    /// `$` and `#` are valid in Oracle names (`V$SESSION`, `SYS.OBJ$`,
    /// `ORDER#`) but stay refused: the allow-list is shared by every
    /// dialect, and `#` starts a comment in MySQL and `$` a parameter or a
    /// dollar quote in PostgreSQL, if the name were ever used unquoted. A
    /// name that needs them is not built from runtime data here.
    #[test]
    fn oracle_dollar_and_hash_names_stay_refused() {
        for bad in ["V$SESSION", "OBJ$", "ORDER#", "A#B"] {
            assert_eq!(SqlIdent::new(bad), Err(SqlGuardError::IllegalChar), "{bad:?}");
        }
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
