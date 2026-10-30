//! Fuzz target (features/sql-browser.md Phase 2): `classify` never panics,
//! never fails internally, and never yields an empty requirement set for a
//! statement that is not transaction control. The same invariants are
//! property-tested in `src/pg/tests.rs`, `src/my/tests.rs` and
//! `src/tsql/tests.rs` (`check_invariants`). Flag bit 16 selects MySQL /
//! MariaDB (T127); bit 128 selects T-SQL (T128); bits 128, 32 and 16 all set
//! select Oracle (T129, `src/ora/tests.rs`).

#![no_main]

use bv_sql_classify::{
    classify, Dialect, LexerSettings, NameContext, NameMatch, Reason, Refusal, SqlCapability, SqlTarget,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte: session flags. The rest: the SQL text, if it is UTF-8.
    let Some((&flags, rest)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let search_path: Vec<String> = if flags & 4 == 0 {
        vec!["pg_catalog".into(), "public".into()]
    } else {
        vec!["public".into(), "pg_catalog".into()]
    };
    let current_schema = (flags & 8 == 0).then(|| "public".to_string());
    let ctx = NameContext {
        database_read_only: flags & 2 != 0,
        ..NameContext::postgres("db", current_schema, search_path)
    };
    let name_match = |bits: u8| match bits & 3 {
        0 => NameMatch::AsciiCaseInsensitive,
        1 => NameMatch::AsciiCaseSensitive,
        _ => NameMatch::Exact,
    };
    // Oracle (T129) takes T-SQL's catalog bits 4-5 = 3, which `name_match`
    // reads exactly as 2, so T-SQL loses no coverage. Bit 6 picks the schema.
    let (dialect, lexer, ctx) = if flags & 0b1011_0000 == 0b1011_0000 {
        let schema = if flags & 64 == 0 { "APP" } else { "Mixed" };
        (Dialect::Oracle, LexerSettings::Oracle, NameContext::oracle("PDB", schema))
    } else if flags & 128 != 0 {
        let lexer = LexerSettings::MsSql {
            quoted_identifier: flags & 1 == 0,
            names: name_match(flags >> 2),
            catalogs: name_match(flags >> 4),
        };
        let schema = if flags & 64 == 0 { "dbo" } else { "sales" };
        let ctx = NameContext { database_read_only: flags & 2 != 0, ..NameContext::mssql("app", Some(schema.into())) };
        (Dialect::MsSql, lexer, ctx)
    } else if flags & 16 == 0 {
        (Dialect::PostgreSql, LexerSettings::PostgreSql { standard_conforming_strings: flags & 1 == 0 }, ctx)
    } else {
        let lexer = LexerSettings::MySql {
            ansi_quotes: flags & 1 != 0,
            no_backslash_escapes: flags & 4 != 0,
            fold_table_names: flags & 32 != 0,
        };
        let dialect = if flags & 64 == 0 { Dialect::MySql } else { Dialect::MariaDb };
        let ctx = NameContext {
            database_read_only: flags & 2 != 0,
            ..NameContext::mysql((flags & 8 == 0).then(|| "app".to_string()))
        };
        (dialect, lexer, ctx)
    };

    match classify(dialect, lexer, text, &ctx) {
        Ok(statements) => {
            let mut last_end = 0;
            for s in &statements {
                assert!(s.tx_control || !s.required.is_empty(), "empty requirement set");
                assert!(s.span.start >= last_end && s.span.start < s.span.end && s.span.end <= text.len());
                assert!(text.is_char_boundary(s.span.start) && text.is_char_boundary(s.span.end));
                assert!(s.required.windows(2).all(|w| w[0] < w[1]));
                for (cap, target) in &s.required {
                    assert!(!matches!(cap, SqlCapability::Export | SqlCapability::Script));
                    if let SqlTarget::Object(o) = target {
                        assert!(!o.catalog.is_empty() && !o.name.is_empty());
                    }
                }
                last_end = s.span.end;
            }
        }
        Err(u) => {
            // A panic inside the classifier is turned into InternalError so
            // a caller is refused, not crashed. The fuzzer must still see it.
            assert_ne!(u.reason, Reason::InternalError, "classifier failed internally");
            assert!(u.refusal == Refusal::Never || u.span.is_some());
        }
    }
});
