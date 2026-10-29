//! Statement classification for BastionVault's SQL browser
//! (features/sql-browser.md §4, T125 Phase 2).
//!
//! [`classify`] splits SQL text into statements and maps each to the SQL
//! privileges (§3.1) it uses, or refuses it. It is a pure function: no I/O,
//! no async, no driver types. Refusal is the default.

// Guarantees, each backed by tests in `pg/tests.rs` and the fuzz target:
// - every statement node is classified, not the leading keyword (§4.3);
// - the caller gets exact byte spans to execute, one per round trip;
// - the spans and literals are found by a lexer that follows the server's
//   rules, and the parser must agree with it on every opaque region;
// - a non-transaction-control statement never has an empty requirement set.

#![forbid(unsafe_code)]

mod model;
mod pg;

pub use model::{
    ClassifiedStatement, Dialect, LexerSettings, NameContext, ObjectKind, ObjectRef, Reason, Refusal, SqlCapability,
    SqlTarget, StatementKind, Unclassifiable,
};

/// Largest input accepted, in bytes: the script limit of §8.2 and the
/// plugin runtime's payload cap.
pub const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// Most statements accepted in one input. The script endpoint's own default
/// (1,000, §8.2) is lower; this is the hard ceiling.
pub const MAX_STATEMENTS: usize = 10_000;

/// Deepest `(` / `[` nesting accepted in one statement.
pub const MAX_NESTING: usize = 32;

/// The parser's recursion budget. It bounds stack use, and a statement that
/// exhausts it is unclassifiable, never truncated.
pub const PARSER_RECURSION_LIMIT: usize = 48;

/// Classify every statement of `text`, all or nothing (§4.1).
///
/// `Ok` holds one entry per statement, in order; an input with no statement
/// (empty, or only comments and `;`) yields an empty list. The first refused
/// statement makes the whole call `Err`, which names it (§8.2: one refused
/// statement refuses the script).
pub fn classify(
    dialect: Dialect,
    lexer: LexerSettings,
    text: &str,
    ctx: &NameContext,
) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    classify_each(dialect, lexer, text, ctx)?.into_iter().collect()
}

/// Like [`classify`], but one result per statement, so a caller can show
/// which statements are refused and why. `Err` only when the input cannot be
/// split at all (too large, a control character, an unterminated literal),
/// in which case nothing in it may run.
pub fn classify_each(
    dialect: Dialect,
    lexer: LexerSettings,
    text: &str,
    ctx: &NameContext,
) -> Result<Vec<Result<ClassifiedStatement, Unclassifiable>>, Unclassifiable> {
    let work = move || match (dialect, lexer) {
        (Dialect::PostgreSql, LexerSettings::PostgreSql { standard_conforming_strings }) => {
            pg::classify_each(text, standard_conforming_strings, ctx)
        }
    };
    // The parser recurses with frames of tens of kilobytes in unoptimised
    // builds, so its recursion budget alone does not keep it inside a 2 MiB
    // thread stack, nor inside whatever stack the caller has left. A stack
    // overflow aborts the process; it runs on a stack of known size instead.
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("bv-sql-classify".into())
            .stack_size(CLASSIFY_STACK_BYTES)
            .spawn_scoped(scope, work);
        match spawned {
            // A panic in the parser refuses the input rather than allowing it.
            Ok(handle) => handle.join().unwrap_or_else(|_| Err(Unclassifiable::whole(Reason::InternalError))),
            Err(_) => Err(Unclassifiable::whole(Reason::InternalError)),
        }
    })
}

/// `text` with its literals replaced by `?` and its comments removed, for
/// records that must not hold the data a statement carries (§11: the
/// journal's default `redacted` mode). The same lexer that splits statements
/// finds the literals; input it cannot lex is refused, never passed through.
pub fn redact(dialect: Dialect, lexer: LexerSettings, text: &str) -> Result<String, Unclassifiable> {
    match (dialect, lexer) {
        (Dialect::PostgreSql, LexerSettings::PostgreSql { standard_conforming_strings }) => {
            pg::redact(text, standard_conforming_strings).map_err(Unclassifiable::whole)
        }
    }
}

/// Stack reserved for one classification (virtual; pages are committed only
/// when touched). Sized for the deepest input the limits above admit, with
/// room to spare in an unoptimised build.
pub const CLASSIFY_STACK_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// The spellings must match `bv_kernel_api::policy::sql::SqlCapability`
    /// and the policy language, or the plugin would ask for capabilities no
    /// policy can grant.
    #[test]
    fn names_match_the_policy_vocabulary() {
        let expected = [
            "sql_select",
            "sql_insert",
            "sql_update",
            "sql_delete",
            "sql_alter",
            "sql_create",
            "sql_drop",
            "sql_execute",
            "sql_admin",
            "sql_export",
            "sql_script",
        ];
        let got: Vec<_> = SqlCapability::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(got, expected);
        for c in SqlCapability::ALL {
            assert_eq!(SqlCapability::parse(c.as_str()), Some(c));
        }
        assert_eq!(SqlCapability::parse("SQL_SELECT"), None);
    }

    fn redact_pg(text: &str, scs: bool) -> Result<String, Unclassifiable> {
        redact(Dialect::PostgreSql, LexerSettings::PostgreSql { standard_conforming_strings: scs }, text)
    }

    #[test]
    fn redaction_removes_every_literal_and_comment() {
        let text = "UPDATE \"Users\" SET email = 'ana@example.com', n = 42, b = E'x\\'y', \
                    c = $tag$secret$tag$, d = X'ff' /* note: pw=hunter2 */ WHERE id = $1 -- 0123\n";
        let out = redact_pg(text, true).unwrap();
        for leaked in ["ana@example.com", "42", "x\\'y", "secret", "ff", "hunter2", "0123"] {
            assert!(!out.contains(leaked), "{leaked} in {out}");
        }
        assert!(out.contains("\"Users\"") && out.contains("$1") && out.contains("email = ?"), "{out}");
        // With standard_conforming_strings off a backslash escapes the quote,
        // so the literal ends where the server says it does.
        let out = redact_pg("SELECT 'a\\' OR 1=1 --'", false).unwrap();
        assert!(!out.contains("OR 1=1"), "{out}");
        assert!(redact_pg("SELECT 'unterminated", true).is_err());
        assert!(redact_pg("SELECT 1\0", true).is_err());
    }
}
