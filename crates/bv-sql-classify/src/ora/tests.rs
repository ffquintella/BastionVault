//! The Oracle corpus (features/sql-browser.md Testing Plan, Classifier;
//! T129): every hazard as a named test, the §4.2 statement table, the
//! session settings, a malformed-input corpus, a lexer differential, then
//! property tests over generated input.

use std::collections::BTreeSet;

use crate::*;

fn ctx() -> NameContext {
    NameContext::oracle("PDB", "APP")
}

fn run(text: &str) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    classify(Dialect::Oracle, LexerSettings::Oracle, text, &ctx())
}

fn each(text: &str) -> Vec<Result<ClassifiedStatement, Unclassifiable>> {
    classify_each(Dialect::Oracle, LexerSettings::Oracle, text, &ctx()).unwrap()
}

fn target(t: &SqlTarget) -> String {
    match t {
        SqlTarget::Server => "server".into(),
        SqlTarget::Object(o) => {
            let kind = match o.kind {
                ObjectKind::Relation => "rel",
                ObjectKind::Sequence => "seq",
                ObjectKind::Routine => "fn",
                ObjectKind::Index => "idx",
                ObjectKind::Type => "type",
                ObjectKind::Collation => "coll",
            };
            format!("{kind}:{}.{}.{}", o.catalog, o.schema.as_deref().unwrap_or("?"), o.name)
        }
    }
}

fn render(s: &ClassifiedStatement) -> BTreeSet<String> {
    s.required.iter().map(|(c, t)| format!("{c} {}", target(t))).collect()
}

#[track_caller]
fn one(text: &str) -> ClassifiedStatement {
    match run(text) {
        Ok(mut v) if v.len() == 1 => v.remove(0),
        other => panic!("{text:?}: expected one classified statement, got {other:?}"),
    }
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
    match run(text) {
        Err(u) => {
            assert_eq!((u.reason, u.refusal), (reason, refusal), "{text:?}: {u:?}");
            if u.refusal == Refusal::Unknown {
                assert!(u.span.is_some(), "an Unknown refusal must carry a span: {text:?}");
            }
        }
        Ok(v) => panic!("{text:?}: expected refusal {reason:?}, got {v:?}"),
    }
}

#[track_caller]
fn never(text: &str, reason: Reason) {
    refused(text, reason, Refusal::Never);
}

/// Refused for the whole input: nothing in it may run.
#[track_caller]
fn whole(text: &str, reason: Reason) {
    match run(text) {
        Err(u) => assert_eq!((u.reason, u.refusal, u.span), (reason, Refusal::Never, None), "{text:?}"),
        Ok(v) => panic!("{text:?}: expected a whole-input refusal, got {v:?}"),
    }
}

#[track_caller]
fn unknown(text: &str) {
    match run(text) {
        Err(u) => {
            assert_eq!(u.refusal, Refusal::Unknown, "{text:?}: {u:?}");
            assert!(u.span.is_some(), "{text:?}");
        }
        Ok(v) => panic!("{text:?}: expected an Unknown refusal, got {v:?}"),
    }
}

#[track_caller]
fn tx(text: &str, kind: StatementKind) {
    let s = one(text);
    assert!(s.tx_control && s.required.is_empty(), "{text:?}: {s:?}");
    assert_eq!(s.kind, kind, "{text:?}");
}

#[track_caller]
fn spans(text: &str) -> Vec<&str> {
    each(text)
        .iter()
        .map(|r| match r {
            Ok(s) => &text[s.span.clone()],
            Err(u) => &text[u.span.clone().unwrap()],
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Hazards, one named test each.
// ---------------------------------------------------------------------------

/// Hazard: `;` hidden in literals, q-quotes, quoted identifiers and comments
/// never splits; every real `;` does, and the second statement is
/// classified, never hidden.
#[test]
fn hazard_multi_statement_smuggling() {
    for text in [
        "SELECT 'x;DELETE FROM t' FROM dual",
        "SELECT N'x; DELETE FROM t' FROM dual",
        "SELECT q'[x'; DELETE FROM t; --]' FROM dual",
        "SELECT q'{;}', Q'<;>', q'(;)', q'!;!', nq'#;#' FROM dual",
        "SELECT \"x;DELETE\" FROM u",
        "SELECT 1 FROM dual /* ; DELETE FROM t; /* not nested */",
        "SELECT 1 FROM dual -- ; DELETE FROM t\n",
    ] {
        let v = run(text).unwrap();
        assert_eq!(v.len(), 1, "{text:?}");
        assert!(render(&v[0]).iter().all(|r| !r.starts_with("sql_delete")), "{text:?}: {v:?}");
    }
    let text = "SELECT 1 FROM dual; DELETE FROM t";
    assert_eq!(spans(text), ["SELECT 1 FROM dual", "DELETE FROM t"]);
    assert_eq!(render(&run(text).unwrap()[1]), BTreeSet::from(["sql_delete rel:PDB.?.T".to_string()]));
    // No backslash escapes: `'a\'` ends at its second quote.
    assert_eq!(spans("SELECT 'a\\' FROM dual; DELETE FROM t").len(), 2);
    // A q-quote ends at the first closing delimiter followed by `'`.
    assert_eq!(spans("SELECT q'[a]' FROM dual; DELETE FROM t"), ["SELECT q'[a]' FROM dual", "DELETE FROM t"]);
    // Two statements in one span never parse as one.
    unknown("SELECT 1 FROM dual DELETE FROM t");
}

/// Hazard: SQL*Plus `/` lines end statements and PL/SQL units; a `/` mid
/// line is division, and one the readers could disagree on is refused.
#[test]
fn hazard_slash_lines() {
    let text = "SELECT a FROM t\n/\nDELETE FROM t\n  /  \nBEGIN NULL; END;\n/\n";
    assert_eq!(spans(text), ["SELECT a FROM t", "DELETE FROM t", "BEGIN NULL; END;"]);
    requires("SELECT 4 / 2 FROM dual", &["sql_select server"]);
    assert_eq!(spans("SELECT 4\n/2 FROM dual"), ["SELECT 4\n/2 FROM dual"]);
    whole("SELECT 1 FROM dual\n/ -- run it\n", Reason::NotOneStatement);
    // `.` alone ends SQL*Plus input without running it.
    whole("SELECT a\n.\nFROM t", Reason::ClientCommand);
    // A `/` line with nothing before it runs nothing (SQL*Plus would run
    // the last statement again).
    assert_eq!(spans("DELETE FROM t WHERE id = 1;\n/\n"), ["DELETE FROM t WHERE id = 1"]);
}

/// Hazard: PL/SQL units are opaque. `;` inside does not split; the span
/// keeps the final `END;`; anonymous blocks need `sql_execute` on the server.
#[test]
fn hazard_plsql_units_are_opaque() {
    let text = "BEGIN\n  UPDATE t SET a = 1;\n  DELETE FROM u;\nEND;\n/\nSELECT 1 FROM dual;";
    let v = run(text).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(&text[v[0].span.clone()], "BEGIN\n  UPDATE t SET a = 1;\n  DELETE FROM u;\nEND;");
    assert_eq!((v[0].kind, v[0].opaque), (StatementKind::Do, true));
    assert_eq!(render(&v[0]), BTreeSet::from(["sql_execute server".to_string()]));
    for text in [
        "DECLARE x NUMBER; BEGIN x := 1; END;",
        "<<outer>> BEGIN NULL; END;",
        "BEGIN FOR i IN 1..3 LOOP NULL; END LOOP; END;",
    ] {
        let s = requires(text, &["sql_execute server"]);
        assert!(s.opaque && s.kind == StatementKind::Do, "{text:?}");
    }
    // Without a `/` the unit runs to the end of the input.
    let text = "CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;\nSELECT 1 FROM dual;";
    assert_eq!(spans(text), [text]);
    // A stored unit is compiled, not run: sql_create, plus sql_alter when
    // it replaces one or adds a body.
    let s = requires(
        "CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;\n/",
        &["sql_create fn:PDB.APP.P", "sql_alter fn:PDB.APP.P"],
    );
    assert!(!s.opaque && s.kind == StatementKind::CreateRoutine);
    requires(
        "CREATE FUNCTION hr.f RETURN NUMBER AUTHID CURRENT_USER IS BEGIN RETURN 1; END;",
        &["sql_create fn:PDB.HR.F"],
    );
    requires("CREATE EDITIONABLE PACKAGE pkg AS PROCEDURE p; END;", &["sql_create fn:PDB.APP.PKG"]);
    requires(
        "CREATE PACKAGE BODY pkg AS PROCEDURE p IS BEGIN NULL; END; END;",
        &["sql_create fn:PDB.APP.PKG", "sql_alter fn:PDB.APP.PKG"],
    );
    let s = requires("CREATE TYPE t_obj AS OBJECT (a NUMBER);", &["sql_create type:PDB.APP.T_OBJ"]);
    assert_eq!(s.kind, StatementKind::CreateType);
    requires("CREATE TYPE BODY t_obj AS END;", &["sql_create type:PDB.APP.T_OBJ", "sql_alter type:PDB.APP.T_OBJ"]);
    // Inline PL/SQL in a query is not classified.
    unknown("WITH FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; SELECT f FROM dual\n/");
}

/// Hazard: a trigger's body runs on every later write, with its owner's
/// rights (T127 / T128 precedent); system triggers are `sql_admin`.
#[test]
fn hazard_triggers() {
    let s = requires(
        "CREATE TRIGGER trg BEFORE INSERT OR UPDATE OF sal ON hr.emp FOR EACH ROW BEGIN :NEW.sal := 1; END;",
        &["sql_create rel:PDB.HR.EMP", "sql_execute server"],
    );
    assert!(s.opaque && s.kind == StatementKind::CreateTrigger);
    requires(
        "CREATE OR REPLACE TRIGGER trg INSTEAD OF INSERT ON v BEGIN NULL; END;",
        &["sql_create rel:PDB.?.V", "sql_alter rel:PDB.?.V", "sql_execute server"],
    );
    for text in [
        "CREATE TRIGGER trg AFTER CREATE ON SCHEMA BEGIN NULL; END;",
        "CREATE TRIGGER trg AFTER DDL ON hr.SCHEMA BEGIN NULL; END;",
        "CREATE TRIGGER trg AFTER LOGON ON DATABASE BEGIN NULL; END;",
    ] {
        requires(text, &["sql_admin server"]);
    }
}

/// Hazard: refused names hidden in a unit or statement, from the words
/// alone, parsed or not; quoted spellings too. A name in a comment or a
/// string literal is not code (dynamic SQL is the documented gap).
#[test]
fn hazard_refused_names_hidden_in_plsql() {
    for text in [
        "BEGIN utl_file.fopen('D', 'f', 'r'); END;",
        "DECLARE f UTL_FILE.FILE_TYPE; BEGIN NULL; END;",
        "BEGIN \"UTL_FILE\".fopen('D', 'f', 'r'); END;",
        "CREATE OR REPLACE PROCEDURE p AS BEGIN DBMS_SCHEDULER.create_job('j'); END;",
        "BEGIN dbms_lob.loadfromfile(a, b, 1); END;",
        "BEGIN x := utl_http.request('http://x'); END;",
        "BEGIN dbms_java.grant_permission('X'); END;",
        "SELECT utl_inaddr.get_host_address('x') FROM dual",
        "SELECT httpuritype('http://x').getclob() FROM dual",
        "SELECT dburitype('/HR/T').getxml() FROM dual",
        "SELECT bfilename('D', 'f') FROM dual",
        "SELECT dbms_cloud_ai.generate('x') FROM dual",
        "SELEC utl_file FROM dual",
        "CREATE OR REPLACE PROCEDURE p AS LANGUAGE C NAME \"x\" LIBRARY lib;",
        "CREATE FUNCTION f RETURN NUMBER AS LANGUAGE JAVA NAME 'X.f() return int';",
        "CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED x AS public class X {};",
        "CREATE OR REPLACE DIRECTORY d AS '/tmp'",
        "CREATE LIBRARY lib AS '/x.so';",
        "GRANT READ ON DIRECTORY d TO u",
        "ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY pw",
        "ALTER DATABASE BACKUP CONTROLFILE TO '/tmp/x'",
        "CREATE PFILE = '/tmp/p.ora' FROM SPFILE",
    ] {
        never(text, Reason::ServerFileOrOsAccess);
    }
    requires("SELECT a FROM t -- utl_file\n", &["sql_select rel:PDB.?.T"]);
    requires("BEGIN x := 'utl_file'; END;", &["sql_execute server"]);
}

/// Hazard: database links reach another server. Any `@` and any DDL on a
/// link never runs; closing one's own link is `sql_admin`.
#[test]
fn hazard_database_links() {
    for text in [
        "SELECT * FROM t@remote",
        "SELECT * FROM hr.t@remote.example.com",
        "INSERT INTO t SELECT * FROM u@l",
        "BEGIN p@remote; END;",
        "CREATE DATABASE LINK l CONNECT TO u IDENTIFIED BY p USING 'x'",
        "CREATE PUBLIC DATABASE LINK l USING 'x'",
        "ALTER DATABASE LINK l CONNECT TO u IDENTIFIED BY p",
        "DROP PUBLIC DATABASE LINK l",
        "CREATE SYNONYM s FOR t@remote",
        "SELECT /*+ DRIVING_SITE(r) */ * FROM r@remote",
    ] {
        never(text, Reason::ServerFileOrOsAccess);
    }
    requires("ALTER SESSION CLOSE DATABASE LINK remote", &["sql_admin server"]);
    // `@` inside a literal is data.
    requires("SELECT 'a@b' FROM dual", &["sql_select server"]);
}

/// Hazard: external tables and inline external data read server files.
#[test]
fn hazard_external_tables() {
    for text in [
        "CREATE TABLE x (a NUMBER) ORGANIZATION EXTERNAL (TYPE oracle_loader DEFAULT DIRECTORY d LOCATION ('f.csv'))",
        "SELECT * FROM EXTERNAL ((a NUMBER) TYPE oracle_loader DEFAULT DIRECTORY d LOCATION ('f'))",
        "SELECT * FROM x EXTERNAL MODIFY (LOCATION ('other.csv'))",
        "ALTER TABLE x LOCATION ('g.csv') EXTERNAL",
    ] {
        never(text, Reason::ServerFileOrOsAccess);
    }
}

/// Hazard: `SELECT … FOR UPDATE` locks what it reads (§4.2).
#[test]
fn hazard_select_for_update() {
    for clause in ["FOR UPDATE", "FOR UPDATE NOWAIT", "FOR UPDATE SKIP LOCKED", "FOR UPDATE OF a"] {
        let s = requires(
            &format!("SELECT * FROM t JOIN hr.u ON t.id = u.id {clause}"),
            &["sql_select rel:PDB.?.T", "sql_update rel:PDB.?.T", "sql_select rel:PDB.HR.U", "sql_update rel:PDB.HR.U"],
        );
        assert_eq!(s.kind, StatementKind::Select);
    }
    // Not read by sqlparser 0.63.
    unknown("SELECT * FROM t FOR UPDATE WAIT 5");
    // Only on the statement itself.
    unknown("SELECT * FROM (SELECT * FROM t FOR UPDATE)");
}

/// Hazard: multi-table `INSERT ALL / FIRST` writes every target.
#[test]
fn hazard_insert_all() {
    let s = requires(
        "INSERT ALL INTO t1 (a) VALUES (x) INTO hr.t2 (b) VALUES (y) SELECT x, y FROM src",
        &["sql_insert rel:PDB.?.T1", "sql_insert rel:PDB.HR.T2", "sql_select rel:PDB.?.SRC"],
    );
    assert_eq!(s.kind, StatementKind::Insert);
    requires(
        "INSERT FIRST WHEN x > (SELECT max(m) FROM lim) THEN INTO t1 VALUES (x) \
         ELSE INTO t2 VALUES (DEFAULT) SELECT x FROM src",
        &["sql_insert rel:PDB.?.T1", "sql_insert rel:PDB.?.T2", "sql_select rel:PDB.?.SRC", "sql_select rel:PDB.?.LIM"],
    );
    // A function in the values is still a call.
    requires(
        "INSERT ALL INTO t1 VALUES (hr.f(x)) SELECT x FROM src",
        &["sql_insert rel:PDB.?.T1", "sql_select rel:PDB.?.SRC", "sql_execute fn:PDB.HR.F", "sql_execute fn:PDB.?.HR"],
    );
    unknown("INSERT ALL INTO t1 a (x) VALUES (1) SELECT 1 FROM dual");
}

/// Hazard: `seq.NEXTVAL` advances the sequence (`sql_update`); `CURRVAL`
/// only reads it.
#[test]
fn hazard_sequence_nextval() {
    requires("SELECT s.NEXTVAL FROM dual", &["sql_update seq:PDB.?.S"]);
    requires("SELECT hr.s.currval FROM dual", &["sql_select seq:PDB.HR.S"]);
    requires("INSERT INTO t (id) VALUES (s.NEXTVAL)", &["sql_insert rel:PDB.?.T", "sql_update seq:PDB.?.S"]);
    // A table alias named like the sequence is ambiguous: not classified.
    unknown("SELECT * FROM t s WHERE s.nextval = 1");
}

/// Hazard: optimizer hints are comments the server reads. They change how a
/// statement runs, not what it touches: `Unknown`, never `sql_select`.
#[test]
fn hazard_optimizer_hints() {
    for text in
        ["SELECT /*+ FULL(t) */ * FROM t", "SELECT --+ FULL(t)\n * FROM t", "UPDATE /*+ PARALLEL */ t SET a = 1"]
    {
        refused(text, Reason::OptimizerHint, Refusal::Unknown);
    }
    requires("SELECT /* not a hint */ * FROM t", &["sql_select rel:PDB.?.T"]);
}

/// Hazard: SQL*Plus / SQLcl client commands are not SQL. The whole input is
/// refused; OS and file access through the client is among them.
#[test]
fn hazard_sqlplus_client_commands() {
    for text in [
        "SET ECHO ON\nSELECT 1 FROM dual;",
        "SET DEFINE OFF",
        "SPOOL /tmp/x",
        "@script.sql",
        "@@nested.sql",
        "START script",
        "HOST ls",
        "$ ls",
        "!ls",
        "$ls",
        "EXEC p",
        "EXECUTE IMMEDIATE 'DROP TABLE t'",
        "DEFINE x = 1",
        "PROMPT hi; DELETE FROM t;",
        "CONNECT scott/tiger@db",
        "DESC t",
        "REM comment",
        "WHENEVER SQLERROR EXIT",
        "VARIABLE x NUMBER",
        "PRINT x",
        "COLUMN a FORMAT a10",
        "SELECT 1 FROM dual;\nSHOW ERRORS",
    ] {
        whole(text, Reason::ClientCommand);
    }
    // SQL*Plus substitution variables.
    whole("SELECT &x FROM dual", Reason::InvalidCharacter);
    // SQL's own SET statements are not client commands.
    tx("SET TRANSACTION READ ONLY", StatementKind::TxBegin);
    requires("SET ROLE ALL", &["sql_admin server"]);
    requires("SET CONSTRAINTS ALL DEFERRED", &["sql_select server"]);
}

/// Hazard: `ALTER SESSION SET CONTAINER` moves the session off the service
/// the credential and the object paths are bound to.
#[test]
fn hazard_alter_session_set_container() {
    for text in [
        "ALTER SESSION SET CONTAINER = cdb$root",
        "alter session set container=pdb2 service=svc",
        "ALTER SESSION SET NLS_SORT = BINARY CONTAINER = cdb$root",
        "ALTER SESSION SET \"CONTAINER\" = x",
    ] {
        never(text, Reason::SessionScopeChange);
    }
}

/// Hazard: `SET TRANSACTION READ WRITE` lifts the read-only guard (§5.3),
/// in a statement or inside a block.
#[test]
fn hazard_set_transaction_read_write() {
    never("SET TRANSACTION READ WRITE", Reason::ReadOnlyGuardChange);
    never("set transaction read write name 'x'", Reason::ReadOnlyGuardChange);
    never("BEGIN COMMIT; SET TRANSACTION READ WRITE; DELETE FROM t; END;", Reason::ReadOnlyGuardChange);
    never("SET TRANSACTION READ WRITE ISOLATION LEVEL SERIALIZABLE", Reason::ReadOnlyGuardChange);
}

/// Hazard: dynamic SQL hides the real statement: opaque `sql_execute` on
/// the server. `CALL` is opaque `sql_execute` on the routine.
#[test]
fn hazard_dynamic_sql() {
    for text in [
        "BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
        "DECLARE c NUMBER; BEGIN c := DBMS_SQL.OPEN_CURSOR; END;",
        "SELECT dbms_xmlgen.getxml('select * from secret') FROM dual",
        "SELECT xmlquery('ora:view(\"SECRET\")' RETURNING CONTENT) FROM dual",
        "SELECT sys.dbms_xmlquery.getxml('select 1 from dual') FROM dual",
        "CALL dbms_sql.parse(1)",
    ] {
        let s = requires(text, &["sql_execute server"]);
        assert!(s.opaque, "{text:?}");
    }
    let s = requires("CALL hr.p(1, 'a', NULL, -2)", &["sql_execute fn:PDB.HR.P", "sql_execute fn:PDB.?.HR"]);
    assert!(s.opaque && s.kind == StatementKind::Call);
    requires("CALL p()", &["sql_execute fn:PDB.?.P"]);
    requires("CALL hr.pkg.p(a => 1)", &["sql_execute fn:PDB.HR.PKG"]);
    requires("CALL dbms_output.put_line('x')", &["sql_execute fn:PDB.SYS.DBMS_OUTPUT"]);
    // Constant arguments only; binds are never bound by the caller.
    unknown("CALL p(x)");
    unknown("CALL p((SELECT 1 FROM dual))");
    unknown("CALL f() INTO :x");
    // Unreviewed supplied packages are not classified.
    unknown("CALL dbms_session.set_role('r')");
}

/// Hazard: side-effecting functions, including Oracle's parameterless calls
/// without parentheses (§4.3 function table).
#[test]
fn hazard_side_effecting_functions() {
    requires(
        "SELECT NVL(a, 0), DECODE(b, 1, 'x'), TO_CHAR(SYSDATE, 'YYYY'), SUBSTR(c, 1, 2) FROM t",
        &["sql_select rel:PDB.?.T"],
    );
    requires(
        "SELECT SYSDATE, USER, ROWNUM, SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual",
        &["sql_select server"],
    );
    requires(
        "SELECT ROW_NUMBER() OVER (ORDER BY a), LISTAGG(a, ',') WITHIN GROUP (ORDER BY a) FROM t",
        &["sql_select rel:PDB.?.T"],
    );
    let s = requires("SELECT my_func(1) FROM dual", &["sql_execute server"]);
    assert!(s.opaque);
    requires("SELECT row_number() FROM dual", &["sql_execute server"]);
    // No column can be meant where no table is in scope: a call.
    requires("SELECT f FROM dual", &["sql_execute server"]);
    requires("INSERT INTO t VALUES (f)", &["sql_insert rel:PDB.?.T", "sql_execute server"]);
    requires("SELECT * FROM (SELECT f FROM dual) x, t", &["sql_select rel:PDB.?.T", "sql_execute server"]);
    requires("WITH c AS (SELECT g FROM dual) SELECT * FROM c, t", &["sql_select rel:PDB.?.T", "sql_execute server"]);
    requires("SELECT \"SYSDATE\" FROM dual", &["sql_execute server"]);
    // A dotted name whose qualifier is no table in scope is a routine:
    // schema.function or package.function, both checked.
    requires("SELECT hr.f FROM dual", &["sql_execute fn:PDB.HR.F", "sql_execute fn:PDB.?.HR"]);
    requires("SELECT hr.pkg.f(1) FROM dual", &["sql_execute fn:PDB.HR.PKG"]);
    requires("SELECT sys.f(1) FROM dual", &["sql_execute fn:PDB.SYS.F"]);
    requires("SELECT t.a, x.b.c FROM t, u x", &["sql_select rel:PDB.?.T", "sql_select rel:PDB.?.U"]);
    // Reviewed supplied packages are SYS's; unreviewed ones are Unknown.
    requires("SELECT dbms_random.value FROM dual", &["sql_execute fn:PDB.SYS.DBMS_RANDOM"]);
    requires("SELECT dbms_lob.getlength(c) FROM t", &["sql_select rel:PDB.?.T", "sql_execute fn:PDB.SYS.DBMS_LOB"]);
    requires("SELECT dbms_utility.get_time FROM dual", &["sql_execute fn:PDB.SYS.DBMS_UTILITY"]);
    unknown("SELECT dbms_utility.exec_ddl_statement('x') FROM dual");
    unknown("SELECT owa_util.get_cgi_env('x') FROM dual");
    unknown("SELECT sys.utl_raw.cast_to_raw('x') FROM dual");
    // Object methods through an alias are not classified.
    unknown("SELECT x.get_name() FROM t x");
}

/// Hazard: `MERGE … UPDATE … DELETE WHERE` deletes rows too.
#[test]
fn hazard_merge_update_delete() {
    requires(
        "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.a = s.a DELETE WHERE t.a = 0",
        &["sql_select rel:PDB.?.T", "sql_update rel:PDB.?.T", "sql_delete rel:PDB.?.T", "sql_select rel:PDB.?.S"],
    );
    let s = requires(
        "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.a = s.a \
         WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a)",
        &["sql_select rel:PDB.?.T", "sql_update rel:PDB.?.T", "sql_insert rel:PDB.?.T", "sql_select rel:PDB.?.S"],
    );
    assert_eq!(s.kind, StatementKind::Merge);
}

/// Hazard: `RETURNING … INTO` binds outside PL/SQL, which the caller never
/// provides: not classified.
#[test]
fn hazard_returning_into() {
    unknown("UPDATE t SET a = 1 RETURNING a INTO :x");
    unknown("DELETE FROM t WHERE id = 1 RETURNING a INTO :x");
    unknown("INSERT INTO t (a) VALUES (1) RETURNING a INTO :x");
    unknown("SELECT * FROM t WHERE a = :x");
}

/// Hazard: `FLASHBACK TABLE` rewrites a table to an earlier state.
#[test]
fn hazard_flashback() {
    requires("FLASHBACK TABLE t TO BEFORE DROP", &["sql_alter rel:PDB.?.T"]);
    requires("FLASHBACK TABLE t TO BEFORE DROP RENAME TO t2", &["sql_alter rel:PDB.?.T", "sql_create rel:PDB.APP.T2"]);
    requires(
        "FLASHBACK TABLE t, hr.u TO TIMESTAMP SYSTIMESTAMP - INTERVAL '1' HOUR ENABLE TRIGGERS",
        &["sql_alter rel:PDB.?.T", "sql_alter rel:PDB.HR.U"],
    );
    requires("FLASHBACK TABLE t TO SCN 12345", &["sql_alter rel:PDB.?.T"]);
    // The point in time must be a constant expression.
    unknown("FLASHBACK TABLE t TO TIMESTAMP (SELECT x FROM u)");
    unknown("FLASHBACK TABLE t TO SCN f(1)");
    requires("FLASHBACK DATABASE TO RESTORE POINT rp", &["sql_admin server"]);
}

/// Names fold to upper case unquoted and are kept quoted; a name that
/// cannot be folded or is too long is never guessed.
#[test]
fn names_case_folding_quoting_and_length() {
    requires("SELECT * FROM Hr.Emp", &["sql_select rel:PDB.HR.EMP"]);
    requires("SELECT * FROM \"Hr\".\"Emp\"", &["sql_select rel:PDB.Hr.Emp"]);
    requires("SELECT * FROM \"HR\".emp", &["sql_select rel:PDB.HR.EMP"]);
    requires("CREATE TABLE n (a NUMBER)", &["sql_create rel:PDB.APP.N"]);
    requires("CREATE TABLE \"n\" (a NUMBER)", &["sql_create rel:PDB.APP.n"]);
    refused("SELECT * FROM ação", Reason::UnresolvableName, Refusal::Unknown);
    requires("SELECT * FROM \"ação\"", &["sql_select rel:PDB.?.ação"]);
    let long = "x".repeat(128);
    requires(&format!("SELECT * FROM {long}"), &[&format!("sql_select rel:PDB.?.{}", long.to_uppercase())]);
    refused(&format!("SELECT * FROM {long}y"), Reason::UnresolvableName, Refusal::Unknown);
    // 65 two-byte characters: 130 bytes, over the limit at 65 characters.
    refused(&format!("SELECT * FROM \"{}\"", "é".repeat(65)), Reason::UnresolvableName, Refusal::Unknown);
    // PUBLIC is no schema; three-part names are no object.
    unknown("SELECT * FROM public.t");
    unknown("SELECT * FROM a.b.c");
    // DUAL is no object.
    requires("SELECT 1 FROM sys.dual", &["sql_select server"]);
    // A reserved word where the parser took a name: the server never does.
    refused("SELECT a uid FROM t", Reason::ReservedWordAsName, Refusal::Unknown);
    unknown("SELECT * FROM t select");
}

#[test]
fn redaction_removes_every_literal_kind_and_passwords() {
    let text = "UPDATE \"Users\" SET email = 'ana@example.com', n = 42, b = N'nat-secret', \
                c = q'[q-secret]', d = nq'{nq-secret}', e = q'!it''s!' /* pw=hunter2 */ WHERE id = 7 -- 0123\n";
    let out = redact(Dialect::Oracle, LexerSettings::Oracle, text).unwrap();
    for leaked in ["ana@example.com", "42", "nat-secret", "q-secret", "nq-secret", "it''s", "hunter2", "0123", "7"] {
        assert!(!out.contains(leaked), "{leaked} in {out}");
    }
    assert!(out.contains("\"Users\"") && out.contains("email = ?"), "{out}");
    for (text, secret) in [
        ("CREATE USER u IDENTIFIED BY Secr3t", "Secr3t"),
        ("ALTER USER u IDENTIFIED BY \"New pw\" REPLACE oldpw", "oldpw"),
        ("ALTER USER u IDENTIFIED BY \"New pw\" REPLACE oldpw", "New pw"),
        ("SET ROLE r IDENTIFIED BY rolepw", "rolepw"),
        ("CONNECT scott/tiger@db", "tiger"),
    ] {
        let out = redact(Dialect::Oracle, LexerSettings::Oracle, text).unwrap();
        assert!(!out.contains(secret), "{secret} in {out}");
    }
    let out = redact(Dialect::Oracle, LexerSettings::Oracle, "SELECT * FROM t CONNECT BY PRIOR a = b").unwrap();
    assert!(out.contains("PRIOR a = b"), "{out}");
    assert!(redact(Dialect::Oracle, LexerSettings::Oracle, "SELECT q'[unterminated").is_err());
}

// ---------------------------------------------------------------------------
// §4.2 statement table.
// ---------------------------------------------------------------------------

#[test]
fn queries() {
    requires("SELECT a FROM t WHERE b = 1 ORDER BY a", &["sql_select rel:PDB.?.T"]);
    requires("SELECT 1 FROM dual", &["sql_select server"]);
    requires("SELECT 1 AS n FROM dual ORDER BY n", &["sql_select server"]);
    requires(
        "SELECT e.ename, d.dname FROM emp e, dept d WHERE e.deptno = d.deptno(+)",
        &["sql_select rel:PDB.?.EMP", "sql_select rel:PDB.?.DEPT"],
    );
    requires(
        "SELECT LEVEL, ename FROM emp START WITH mgr IS NULL CONNECT BY PRIOR empno = mgr",
        &["sql_select rel:PDB.?.EMP"],
    );
    requires("SELECT * FROM t MINUS SELECT * FROM u", &["sql_select rel:PDB.?.T", "sql_select rel:PDB.?.U"]);
    requires("SELECT * FROM t OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY", &["sql_select rel:PDB.?.T"]);
    requires("SELECT a, SUM(b) FROM t GROUP BY ROLLUP(a)", &["sql_select rel:PDB.?.T"]);
    requires("SELECT * FROM t WHERE a = ANY (SELECT b FROM u)", &["sql_select rel:PDB.?.T", "sql_select rel:PDB.?.U"]);
    requires("SELECT * FROM t PIVOT (SUM(a) FOR b IN (1, 2))", &["sql_select rel:PDB.?.T"]);
    requires(
        "SELECT * FROM t CROSS APPLY (SELECT * FROM u WHERE u.a = t.a)",
        &["sql_select rel:PDB.?.T", "sql_select rel:PDB.?.U"],
    );
    requires("SELECT q'[it's]', N'x', DATE '2020-01-01', INTERVAL '1' DAY FROM dual", &["sql_select server"]);
    requires("WITH c AS (SELECT * FROM t) SELECT * FROM c", &["sql_select rel:PDB.?.T"]);
    requires(
        "WITH a AS (SELECT * FROM b), b AS (SELECT 1 x FROM dual) SELECT * FROM a, b",
        &["sql_select rel:PDB.?.B"],
    );
    requires("SELECT * FROM v$session", &["sql_select rel:PDB.?.V$SESSION"]);
    unknown("SELECT * FROM t AS OF TIMESTAMP SYSTIMESTAMP");
    unknown("SELECT MAX(a) KEEP (DENSE_RANK FIRST ORDER BY b) FROM t");
    unknown("SELECT x.* FROM t a");
}

#[test]
fn writes() {
    requires("INSERT INTO t VALUES (1, 'a')", &["sql_insert rel:PDB.?.T"]);
    requires("INSERT INTO t SELECT * FROM u", &["sql_insert rel:PDB.?.T", "sql_select rel:PDB.?.U"]);
    requires("UPDATE t SET a = 1", &["sql_update rel:PDB.?.T"]);
    requires("UPDATE t x SET x.a = x.a + 1", &["sql_update rel:PDB.?.T", "sql_select rel:PDB.?.T"]);
    requires("DELETE FROM t", &["sql_delete rel:PDB.?.T"]);
    requires("DELETE t WHERE id = 1", &["sql_delete rel:PDB.?.T", "sql_select rel:PDB.?.T"]);
    requires(
        "DELETE FROM t WHERE a IN (SELECT b FROM u WHERE u.c = t.c)",
        &["sql_delete rel:PDB.?.T", "sql_select rel:PDB.?.T", "sql_select rel:PDB.?.U"],
    );
    unknown("UPDATE (SELECT a FROM t) SET a = 1");
    unknown("INSERT INTO (SELECT a FROM t) VALUES (1)");
    unknown("DELETE FROM dual");
    let s = requires(
        "LOCK TABLE t, hr.u IN ROW SHARE MODE NOWAIT",
        &["sql_select rel:PDB.?.T", "sql_update rel:PDB.?.T", "sql_select rel:PDB.HR.U", "sql_update rel:PDB.HR.U"],
    );
    assert_eq!(s.kind, StatementKind::Lock);
    requires("LOCK TABLE t IN EXCLUSIVE MODE WAIT 5", &["sql_select rel:PDB.?.T", "sql_update rel:PDB.?.T"]);
}

#[test]
fn ddl_and_maintenance() {
    requires(
        "CREATE TABLE n (id NUMBER PRIMARY KEY, u_id NUMBER REFERENCES u (id), a NUMBER CHECK (a > 0))",
        &["sql_create rel:PDB.APP.N", "sql_alter rel:PDB.?.U"],
    );
    requires(
        "CREATE TABLE n AS SELECT * FROM t",
        &["sql_create rel:PDB.APP.N", "sql_insert rel:PDB.APP.N", "sql_select rel:PDB.?.T"],
    );
    requires("CREATE GLOBAL TEMPORARY TABLE g (a NUMBER) ON COMMIT PRESERVE ROWS", &["sql_create rel:PDB.APP.G"]);
    requires(
        "CREATE OR REPLACE VIEW v AS SELECT * FROM t",
        &["sql_create rel:PDB.APP.V", "sql_alter rel:PDB.APP.V", "sql_select rel:PDB.?.T"],
    );
    requires("CREATE INDEX i ON t (a)", &["sql_create rel:PDB.?.T", "sql_create idx:PDB.APP.I"]);
    requires("CREATE UNIQUE INDEX hr.i ON hr.t (UPPER(a))", &["sql_create rel:PDB.HR.T", "sql_create idx:PDB.HR.I"]);
    requires("CREATE SEQUENCE s START WITH 1 INCREMENT BY 1 CACHE 20", &["sql_create seq:PDB.APP.S"]);
    requires("CREATE SYNONYM s FOR hr.t", &["sql_create rel:PDB.APP.S"]);
    requires("CREATE PUBLIC SYNONYM s FOR hr.t", &["sql_admin server"]);
    requires("ALTER TABLE t ADD c NUMBER", &["sql_alter rel:PDB.?.T"]);
    requires(
        "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id)",
        &["sql_alter rel:PDB.?.T", "sql_alter rel:PDB.?.U"],
    );
    requires("ALTER TABLE t RENAME TO n", &["sql_alter rel:PDB.?.T", "sql_create rel:PDB.APP.N"]);
    requires("ALTER SEQUENCE s INCREMENT BY 2", &["sql_alter seq:PDB.?.S"]);
    requires("ALTER INDEX i REBUILD ONLINE", &["sql_alter idx:PDB.?.I"]);
    requires("ALTER INDEX i RENAME TO j", &["sql_alter idx:PDB.?.I", "sql_create idx:PDB.APP.J"]);
    requires("ALTER VIEW v COMPILE", &["sql_alter rel:PDB.?.V"]);
    requires("ALTER PACKAGE hr.p COMPILE BODY", &["sql_alter fn:PDB.HR.P"]);
    requires("ALTER TYPE t COMPILE", &["sql_alter type:PDB.?.T"]);
    requires("ALTER TRIGGER tr DISABLE", &["sql_alter server"]);
    requires("RENAME t TO t2", &["sql_alter rel:PDB.?.T", "sql_create rel:PDB.APP.T2"]);
    requires("COMMENT ON TABLE t IS 'x'", &["sql_alter rel:PDB.?.T"]);
    requires("COMMENT ON COLUMN hr.t.c IS 'x'", &["sql_alter rel:PDB.HR.T"]);
    requires("ANALYZE TABLE t COMPUTE STATISTICS", &["sql_alter rel:PDB.?.T"]);
    unknown("ANALYZE TABLE t LIST CHAINED ROWS INTO ct");
    requires("DROP TABLE t", &["sql_drop rel:PDB.?.T"]);
    requires("DROP TABLE IF EXISTS t CASCADE CONSTRAINTS PURGE", &["sql_drop rel:PDB.?.T", "sql_drop server"]);
    requires("DROP INDEX i", &["sql_drop idx:PDB.?.I"]);
    requires("DROP SEQUENCE s", &["sql_drop seq:PDB.?.S"]);
    requires("DROP PACKAGE BODY p", &["sql_drop fn:PDB.?.P"]);
    requires("DROP TYPE t FORCE", &["sql_drop type:PDB.?.T"]);
    requires("DROP TRIGGER tr", &["sql_drop server"]);
    requires("DROP SYNONYM s", &["sql_drop rel:PDB.?.S"]);
    requires("DROP PUBLIC SYNONYM s", &["sql_admin server"]);
    requires("TRUNCATE TABLE t DROP STORAGE", &["sql_drop rel:PDB.?.T"]);
    requires("TRUNCATE TABLE t CASCADE", &["sql_drop rel:PDB.?.T", "sql_drop server"]);
    requires("PURGE TABLE t", &["sql_drop rel:PDB.?.T"]);
    requires("PURGE RECYCLEBIN", &["sql_drop server"]);
    requires("PURGE DBA_RECYCLEBIN", &["sql_admin server"]);
    unknown("ALTER TABLE t ADD (c NUMBER)");
    unknown("CREATE BITMAP INDEX i ON t (a)");
    unknown("CREATE SCHEMA AUTHORIZATION hr CREATE TABLE t (a NUMBER)");
    unknown("EXPLAIN PLAN FOR SELECT * FROM t");
}

#[test]
fn admin_statements() {
    for text in [
        "GRANT SELECT ON t TO u",
        "REVOKE ALL ON t FROM u",
        "CREATE USER u IDENTIFIED BY pw",
        "ALTER USER u ACCOUNT LOCK",
        "DROP USER u CASCADE",
        "CREATE ROLE r",
        "CREATE PROFILE p LIMIT SESSIONS_PER_USER 1",
        "AUDIT SELECT ON t",
        "NOAUDIT SELECT ON t",
        "ALTER SYSTEM SET processes = 300",
        "ALTER SYSTEM KILL SESSION '1,2'",
        "ALTER DATABASE OPEN",
        "ALTER PLUGGABLE DATABASE p OPEN",
        "CREATE TABLESPACE ts DATAFILE 'x.dbf' SIZE 10M",
        "SET TRANSACTION USE ROLLBACK SEGMENT rs",
        "COMMIT FORCE '1.2.3'",
        "ALTER SESSION SET EDITION = e1",
        "ALTER SESSION SET EVENTS '10046 trace name context forever'",
        "ALTER SESSION SET SQL_TRACE = TRUE",
        "ALTER SESSION SET \"_hidden\" = TRUE",
        "ALTER SESSION ENABLE PARALLEL DML",
        "ALTER SESSION DISABLE COMMIT IN PROCEDURE",
        "ALTER SESSION ENABLE RESUMABLE TIMEOUT 60",
    ] {
        let s = one(text);
        assert!(render(&s).contains("sql_admin server"), "{text:?}: {s:?}");
    }
}

#[test]
fn transactions_and_session_state() {
    tx("COMMIT", StatementKind::TxCommit);
    tx("COMMIT WORK", StatementKind::TxCommit);
    tx("COMMIT COMMENT 'x' WRITE NOWAIT", StatementKind::TxCommit);
    tx("ROLLBACK", StatementKind::TxRollback);
    tx("ROLLBACK WORK", StatementKind::TxRollback);
    tx("ROLLBACK TO SAVEPOINT sp", StatementKind::TxSavepoint);
    tx("ROLLBACK TO sp", StatementKind::TxSavepoint);
    tx("SAVEPOINT sp", StatementKind::TxSavepoint);
    tx("SET TRANSACTION READ ONLY", StatementKind::TxBegin);
    tx("SET TRANSACTION READ ONLY NAME 'x'", StatementKind::TxBegin);
    tx("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", StatementKind::TxBegin);
    tx("SET TRANSACTION ISOLATION LEVEL READ COMMITTED", StatementKind::TxBegin);
    tx("SET TRANSACTION NAME 'x'", StatementKind::TxBegin);
    // Transaction control never carries anything else.
    unknown("COMMIT SELECT");
    unknown("SAVEPOINT a b");
    for text in [
        "ALTER SESSION SET CURRENT_SCHEMA = hr",
        "ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD' TIME_ZONE = '+00:00'",
        "ALTER SESSION SET NLS_LANGUAGE = 'AMERICAN' NLS_TERRITORY = AMERICA",
        "ALTER SESSION SET ISOLATION_LEVEL = READ COMMITTED",
        "ALTER SESSION SET TIME_ZONE = DBTIMEZONE",
    ] {
        let s = requires(text, &["sql_select server"]);
        assert_eq!(s.kind, StatementKind::SetSession, "{text:?}");
    }
    requires("ALTER SESSION SET NLS_SORT = BINARY SQL_TRACE = TRUE", &["sql_select server", "sql_admin server"]);
    unknown("ALTER SESSION SET CURRENT_SCHEMA = (SELECT 1 FROM dual)");
}

#[test]
fn dialect_and_settings_must_match() {
    let pg = LexerSettings::PostgreSql { standard_conforming_strings: true };
    for (d, s) in
        [(Dialect::Oracle, pg), (Dialect::PostgreSql, LexerSettings::Oracle), (Dialect::MsSql, LexerSettings::Oracle)]
    {
        let u = classify(d, s, "SELECT 1 FROM dual", &ctx()).unwrap_err();
        assert_eq!((u.reason, u.refusal), (Reason::DialectMismatch, Refusal::Never));
        assert_eq!(redact(d, s, "SELECT 1 FROM dual").unwrap_err().reason, Reason::DialectMismatch);
    }
    let bad = NameContext { current_catalog: String::new(), ..ctx() };
    let u = classify(Dialect::Oracle, LexerSettings::Oracle, "SELECT 1 FROM dual", &bad).unwrap_err();
    assert_eq!(u.reason, Reason::InvalidContext);
}

// ---------------------------------------------------------------------------
// Malformed input and the lexer differential.
// ---------------------------------------------------------------------------

#[test]
fn malformed_input_corpus() {
    for (text, reason) in [
        ("SELECT 'abc", Reason::UnterminatedLiteral),
        ("SELECT q'[abc]", Reason::UnterminatedLiteral),
        ("SELECT \"abc", Reason::UnterminatedLiteral),
        ("SELECT /* abc", Reason::UnterminatedLiteral),
        ("SELECT 1 FROM dual\0", Reason::ControlCharacter),
        ("SELECT\u{0b}1", Reason::ControlCharacter),
        ("SELECT 1 -- x\rDELETE FROM t", Reason::ControlCharacter),
        ("SELECT 1 \\ 2", Reason::InvalidCharacter),
        ("SELECT 2fa FROM t", Reason::InvalidCharacter),
        ("SELECT 1e FROM dual", Reason::InvalidCharacter),
        ("SELECT 0x1F FROM dual", Reason::InvalidCharacter),
        ("SELECT 1.5f FROM dual", Reason::InvalidCharacter),
        ("SELECT\u{a0}1", Reason::InvalidCharacter),
        ("SELECT \"\" FROM t", Reason::InvalidCharacter),
        ("SELECT q' x ' FROM dual", Reason::InvalidCharacter),
        ("SELECT q']x]' FROM dual", Reason::InvalidCharacter),
    ] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.statement_index), (reason, Refusal::Never, None), "{text:?}");
    }
    let deep = format!("SELECT {}1{} FROM dual", "(".repeat(40), ")".repeat(40));
    assert_eq!(run(&deep).unwrap_err().reason, Reason::NestingTooDeep);
    let big = "SELECT 1 FROM dual;".repeat(MAX_TEXT_BYTES / 19 + 1);
    assert_eq!(run(&big).unwrap_err().reason, Reason::InputTooLarge);
    for text in ["SELEC 1", "SELECT FROM WHERE", "INSERT INTO", "UPDATE SET", "))((", "SELECT 1 +", "a.b.", "BEGIN"] {
        if let Err(u) = run(text) {
            assert!(u.span.is_some() || u.refusal == Refusal::Never, "{text:?}: {u:?}");
        }
    }
    assert!(run("").unwrap().is_empty());
    assert!(run("  ; ;-- c\n/\n").unwrap().is_empty());
}

/// The parser's tokenizer must agree with this crate's lexer on every
/// literal, q-quote, quoted identifier and comment, or the statement is
/// not classified (`differential.rs`).
#[test]
fn differential_lexer_agreement() {
    for text in [
        "SELECT 'a''b', N'c', n'd', q'[e]f]', Q'{g}', q'<h>', q'(i)', q'!j!', nq'#k#', NQ'|l|' FROM dual",
        "SELECT \"Mixed Case\", \"x;y\" FROM \"T\" /* c */ -- d\n",
        "SELECT 1 FROM dual -- crlf\r\n WHERE 1 = 1",
        "SELECT a.b, c.d FROM t a, u c WHERE a.x = c.y",
    ] {
        assert!(run(text).is_ok(), "{text:?}: {:?}", run(text));
    }
    // Where they disagree the statement never runs.
    for text in ["SELECT x'1F' FROM dual", "SELECT \"a\"\"b\" FROM dual"] {
        never(text, Reason::LexerDisagreement);
    }
    // In a unit, sqlparser reads `$$` as a dollar-quoted string: a unit
    // with two inquiry directives is refused, one is not classified.
    never("BEGIN x := $$PLSQL_UNIT || $$PLSQL_LINE; END;", Reason::LexerDisagreement);
    unknown("BEGIN $IF $$DEBUG $THEN NULL; $END END;");
    requires("BEGIN NULL; $IF TRUE $THEN NULL; $END END;", &["sql_execute server"]);
}

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
                let unit = matches!(
                    s.kind,
                    StatementKind::Do
                        | StatementKind::CreateRoutine
                        | StatementKind::CreateType
                        | StatementKind::CreateTrigger
                );
                assert!(unit || !body.contains(';') || body.contains(['\'', '"', '-', '/']), "{body:?}");
                assert!(!body.contains('@') || body.contains(['\'', '"', '-', '/']), "{body:?}");
                assert!(s.required.windows(2).all(|w| w[0] < w[1]), "sorted and deduplicated");
                for (cap, t) in &s.required {
                    assert!(!matches!(cap, SqlCapability::Export | SqlCapability::Script));
                    if let SqlTarget::Object(o) = t {
                        assert!(o.catalog == "PDB" && !o.name.is_empty() && o.name.len() <= 128, "{o:?}");
                    }
                }
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
            assert_ne!(u.reason, Reason::InternalError, "classifier failed internally");
        }
    }
}

mod props {
    use proptest::prelude::*;

    use super::*;

    fn cases() -> u32 {
        std::env::var("BV_SQL_CLASSIFY_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000)
    }

    const FRAGMENTS: &[&str] = &[
        "SELECT",
        "FROM",
        "dual",
        "t",
        "hr.t",
        "WHERE",
        "INSERT",
        "ALL",
        "FIRST",
        "INTO",
        "VALUES",
        "UPDATE",
        "SET",
        "DELETE",
        "MERGE",
        "USING",
        "WHEN",
        "THEN",
        "BEGIN",
        "END",
        "DECLARE",
        "CREATE",
        "OR",
        "REPLACE",
        "PROCEDURE",
        "PACKAGE",
        "BODY",
        "TRIGGER",
        "TYPE",
        "ON",
        "FOR",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "TRANSACTION",
        "READ",
        "ONLY",
        "WRITE",
        "ALTER",
        "SESSION",
        "CONTAINER",
        "CURRENT_SCHEMA",
        "CALL",
        "LOCK",
        "TABLE",
        "IN",
        "MODE",
        "TRUNCATE",
        "DROP",
        "FLASHBACK",
        "GRANT",
        "ECHO",
        "SPOOL",
        "EXEC",
        "utl_file",
        "dbms_sql.parse(1)",
        "dbms_random.value",
        "s.NEXTVAL",
        "f",
        "hr.f(1)",
        "SYSDATE",
        "ROWNUM",
        "@",
        "@link",
        "q'[a;b]'",
        "q'{x}'",
        "nq'<y>'",
        "q'",
        "'a''b'",
        "N'n'",
        "\"Q\"",
        "\"a\"\"b\"",
        "x'1F'",
        "$IF",
        "$$X",
        "1",
        "1e5",
        ".5",
        "1..2",
        "-- c\n",
        "--+ h\n",
        "/*+ h */",
        "/* c */",
        "\n/\n",
        "\n.\n",
        ";",
        ",",
        "(",
        ")",
        "*",
        "=",
        "+",
        "-",
        ".",
        ":x",
        " ",
        "\n",
        "\r\n",
        "\r",
        "\t",
        "'",
        "\"",
        "/",
        "\\",
        "&",
        "!",
        "$",
        "?",
        "#",
        "<<",
        ">>",
    ];

    fn soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.join(" "))
    }

    fn glued_soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.concat())
    }

    fn context() -> impl Strategy<Value = NameContext> {
        prop::sample::select(&["APP", "HR", "Mixed"][..]).prop_map(|s| NameContext::oracle("PDB", s))
    }

    fn run_with(text: &str, c: &NameContext) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
        classify(Dialect::Oracle, LexerSettings::Oracle, text, c)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_text_holds_the_invariants(text in any::<String>(), c in context()) {
            check_invariants(&text, &run_with(&text, &c));
        }

        #[test]
        fn sql_soup_holds_the_invariants(text in soup(), c in context()) {
            check_invariants(&text, &run_with(&text, &c));
        }

        #[test]
        fn glued_sql_soup_holds_the_invariants(text in glued_soup(), c in context()) {
            check_invariants(&text, &run_with(&text, &c));
        }

        #[test]
        fn classification_is_deterministic(text in soup()) {
            prop_assert_eq!(run(&text), run(&text));
        }

        /// Redaction never fails where classification could lex, and what
        /// it returns holds no literal, number or comment at all.
        #[test]
        fn redaction_follows_the_lexer(text in soup()) {
            let classified = classify_each(Dialect::Oracle, LexerSettings::Oracle, &text, &ctx());
            let redacted = redact(Dialect::Oracle, LexerSettings::Oracle, &text);
            if let Ok(out) = &redacted {
                let toks = super::super::lexer::lex(out).map_err(|e| format!("{e:?} in {out:?}"));
                prop_assert!(toks.is_ok(), "{:?}", toks);
                let left: Vec<_> = toks.unwrap().into_iter().filter(|t| {
                    t.is_comment() || matches!(t.kind, super::super::lexer::TokKind::Str(_) | super::super::lexer::TokKind::Number)
                }).collect();
                prop_assert!(left.is_empty(), "{:?} in {:?}", left, out);
            }
            if classified.is_ok() {
                prop_assert!(redacted.is_ok());
            }
        }

        /// Statements joined by `;` or `/` lines, with comments between,
        /// come back as exactly those statements.
        #[test]
        fn spans_are_the_statements(
            picks in prop::collection::vec(0usize..8, 1..12),
            seps in prop::collection::vec(
                prop::sample::select(&[";", " ; ", ";\n-- c\n", "; /* x; */ ", ";;", "\n/\n", ";\n/\n"][..]),
                12,
            ),
        ) {
            const STATEMENTS: [&str; 8] = [
                "SELECT 1 FROM dual", "SELECT 'a;b' FROM t", "DELETE FROM t WHERE a = q'[x;]'", "UPDATE t SET a = 1",
                "INSERT INTO t VALUES (';')", "SAVEPOINT a", "SELECT \"x;\" FROM u /* ; */ WHERE b = 2", "COMMIT",
            ];
            let mut text = String::new();
            for (i, p) in picks.iter().enumerate() {
                text.push_str(STATEMENTS[*p]);
                text.push_str(seps[i]);
            }
            let each = classify_each(Dialect::Oracle, LexerSettings::Oracle, &text, &ctx()).unwrap();
            let spans: Vec<&str> = each
                .iter()
                .map(|r| match r {
                    Ok(s) => &text[s.span.clone()],
                    Err(u) => &text[u.span.clone().unwrap()],
                })
                .collect();
            let want: Vec<&str> = picks.iter().map(|p| STATEMENTS[*p]).collect();
            prop_assert_eq!(spans, want);
            prop_assert!(each.iter().all(Result::is_ok), "{:?}", each);
        }
    }
}

/// Inputs shaped to cost quadratic time or unbounded stack: an operator
/// chain the parser builds as a left-deep tree in a loop (its recursion
/// limit does not see it), and a 3.6 MB line of `/` tokens the splitter
/// must place on their line without rescanning it.
#[test]
fn hostile_shapes_are_refused_in_bounded_time_and_stack() {
    requires(&format!("SELECT 1{} FROM dual", "+1".repeat(1000)), &["sql_select server"]);
    for text in [
        format!("SELECT 1{} FROM dual", "+1".repeat(100_000)),
        format!("SELECT 1 FROM dual WHERE a = 1{}", " OR a = 1".repeat(5_000)),
        format!("SELECT 1 FROM dual{}", " UNION SELECT 1 FROM dual".repeat(100_000)),
        format!("SELECT 1 FROM dual WHERE a{} IS NULL", " IS NULL".repeat(100_000)),
    ] {
        never(&text, Reason::NestingTooDeep);
    }
    let start = std::time::Instant::now();
    let text = format!("SELECT 1{} FROM dual", " / 1".repeat(900_000));
    never(&text, Reason::NestingTooDeep);
    let text = format!("CONNECT{}", " connect".repeat(500_000));
    assert!(redact(Dialect::Oracle, LexerSettings::Oracle, &text).is_ok());
    assert!(start.elapsed() < std::time::Duration::from_secs(60), "{:?}", start.elapsed());
}
