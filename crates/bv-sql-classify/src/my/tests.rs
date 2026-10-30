//! The MySQL / MariaDB corpus (features/sql-browser.md Testing Plan,
//! Classifier; T127): every §4.3 hazard as a named test, the §4.2 statement
//! table, the session settings, a malformed-input corpus, then property
//! tests over generated input.

use std::collections::BTreeSet;

use crate::*;

fn ctx() -> NameContext {
    NameContext::mysql(Some("app".into()))
}

fn st(ansi_quotes: bool, no_backslash_escapes: bool) -> LexerSettings {
    LexerSettings::MySql { ansi_quotes, no_backslash_escapes, fold_table_names: false }
}

fn run_with(
    d: Dialect,
    s: LexerSettings,
    text: &str,
    ctx: &NameContext,
) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    classify(d, s, text, ctx)
}

fn run(text: &str) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    run_with(Dialect::MySql, st(false, false), text, &ctx())
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
            assert_eq!(o.catalog, "def", "MySQL objects are in catalog def");
            format!("{kind}:{}.{}", o.schema.as_deref().unwrap_or("?"), o.name)
        }
    }
}

fn render(s: &ClassifiedStatement) -> BTreeSet<String> {
    s.required.iter().map(|(c, t)| format!("{c} {}", target(t))).collect()
}

#[track_caller]
fn one_with(d: Dialect, s: LexerSettings, text: &str, ctx: &NameContext) -> ClassifiedStatement {
    match run_with(d, s, text, ctx) {
        Ok(mut v) if v.len() == 1 => v.remove(0),
        other => panic!("{text:?}: expected one classified statement, got {other:?}"),
    }
}

#[track_caller]
fn requires_with(d: Dialect, ctx: &NameContext, text: &str, expected: &[&str]) -> ClassifiedStatement {
    let s = one_with(d, st(false, false), text, ctx);
    let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(render(&s), want, "{text:?}");
    s
}

#[track_caller]
fn requires(text: &str, expected: &[&str]) -> ClassifiedStatement {
    requires_with(Dialect::MySql, &ctx(), text, expected)
}

#[track_caller]
fn refused_with(d: Dialect, s: LexerSettings, text: &str, reason: Reason, refusal: Refusal) {
    match run_with(d, s, text, &ctx()) {
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
fn refused(text: &str, reason: Reason, refusal: Refusal) {
    refused_with(Dialect::MySql, st(false, false), text, reason, refusal);
    refused_with(Dialect::MariaDb, st(false, false), text, reason, refusal);
}

#[track_caller]
fn never(text: &str, reason: Reason) {
    refused(text, reason, Refusal::Never);
}

#[track_caller]
fn unknown(text: &str) {
    match run(text) {
        Err(u) => assert_eq!(u.refusal, Refusal::Unknown, "{text:?}: {u:?}"),
        Ok(v) => panic!("{text:?}: expected an Unknown refusal, got {v:?}"),
    }
}

#[track_caller]
fn tx(text: &str, kind: StatementKind) {
    let s = one_with(Dialect::MySql, st(false, false), text, &ctx());
    assert!(s.tx_control && s.required.is_empty(), "{text:?}: {s:?}");
    assert_eq!(s.kind, kind, "{text:?}");
}

// ---------------------------------------------------------------------------
// §4.3 hazards, one named test each.
// ---------------------------------------------------------------------------

/// Hazard: multi-statement smuggling. The spans are exactly what the server
/// will see as statements; nothing hides in a literal or a comment the
/// server reads differently.
#[test]
fn hazard_multi_statement_smuggling() {
    let text = "SELECT 1; DELETE FROM t";
    let v = run(text).unwrap();
    assert_eq!(v.iter().map(|s| &text[s.span.clone()]).collect::<Vec<_>>(), ["SELECT 1", "DELETE FROM t"]);
    assert_eq!(render(&v[1]), BTreeSet::from(["sql_delete rel:app.t".to_string()]));
    for text in [
        "SELECT 'x;DELETE FROM t'",
        "SELECT \"x;DELETE FROM t\"",
        "SELECT `x;DELETE FROM t` FROM u",
        "SELECT 1 /* ; DELETE FROM t; */",
        "SELECT 1 # ; DELETE FROM t\n",
        "SELECT 1 -- ; DELETE FROM t\n",
        "SELECT 'a\\'; DELETE FROM t; #'",
    ] {
        let v = run(text).unwrap();
        assert_eq!(v.len(), 1, "{text:?}");
        assert!(render(&v[0]).iter().all(|r| !r.starts_with("sql_delete")), "{text:?}: {v:?}");
    }
    // Under NO_BACKSLASH_ESCAPES the same text is two statements, and the
    // DELETE is classified (here refused as an unread string), never hidden.
    let each = classify_each(Dialect::MySql, st(false, true), "SELECT 'a\\'; DELETE FROM t; #'", &ctx()).unwrap();
    assert_eq!(each.len(), 2, "{each:?}");
    assert_eq!(each[0].as_ref().unwrap_err().reason, Reason::LexerSettingUnsupported);
    assert_eq!(render(each[1].as_ref().unwrap()), BTreeSet::from(["sql_delete rel:app.t".to_string()]));
    // `--` without a space is not a comment: `1--1` hides nothing.
    let v = run("SELECT 1--1; DELETE FROM t").unwrap();
    assert_eq!(v.len(), 2);
}

/// Hazard: MySQL / MariaDB executable comments (§4.3): the server runs their
/// content, so any statement holding one never runs; optimizer hints and
/// nested comments too.
#[test]
fn hazard_executable_comments() {
    for text in [
        "SELECT 1 /*! , (SELECT secret FROM s) */",
        "SELECT 1 /*!50000 UNION SELECT secret FROM s */",
        "/*!40101 SET NAMES gbk */",
        "SELECT 1 /*M! , (SELECT secret FROM s) */",
        "SELECT 1 /*m!100000 , 2 */",
        "SELECT /*+ SET_VAR(sql_mode='ANSI_QUOTES') */ 1",
        "UPDATE /*+ NO_INDEX(t) */ t SET a = 1",
    ] {
        never(text, Reason::ExecutableComment);
    }
    // A nested comment: MySQL and MariaDB disagree on where it ends.
    for text in ["SELECT 1 /* /* */ , 2 */", "SELECT 1 /* a /*! b */"] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.span), (Reason::ExecutableComment, Refusal::Never, None), "{text:?}");
    }
    // Ordinary comments are fine.
    requires("SELECT /* ! not executable */ a FROM t", &["sql_select rel:app.t"]);
}

/// Hazard: LOCAL INFILE and the other server file / OS / network access.
/// Always refused; `sql_admin` does not unlock them (§4.2).
#[test]
fn hazard_local_infile_and_file_access() {
    for text in [
        "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t",
        "LOAD DATA INFILE '/var/lib/mysql-files/x' INTO TABLE t",
        "LOAD XML LOCAL INFILE 'x.xml' INTO TABLE t",
        "SELECT * FROM t INTO OUTFILE '/tmp/x'",
        "SELECT a INTO DUMPFILE '/tmp/y' FROM t",
        "TABLE t INTO OUTFILE '/tmp/z'",
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT load_file ('/etc/passwd')",
        "SELECT x.load_file('a') FROM t AS x",
        "SELECT sys_exec('id')",
        "SELECT sys_eval('id')",
        "CREATE FUNCTION f RETURNS STRING SONAME 'udf.so'",
        "INSTALL PLUGIN p SONAME 'p.so'",
        "INSTALL SONAME 'auth_pam'",
        "UNINSTALL PLUGIN p",
        "CREATE TABLE n (a int) DATA DIRECTORY = '/tmp'",
        "CREATE TABLE n (a int) INDEX DIRECTORY = '/tmp'",
        "CREATE TABLE f (a int) ENGINE=FEDERATED CONNECTION='mysql://u:p@h:3306/db/t'",
        "CREATE TABLE f (a int) ENGINE=CONNECT TABLE_TYPE=CSV FILE_NAME='/etc/passwd'",
        "ALTER TABLE t DISCARD TABLESPACE",
        "ALTER TABLE t IMPORT TABLESPACE",
        "CLONE LOCAL DATA DIRECTORY = '/tmp/c'",
        "IMPORT TABLE FROM '/tmp/t.sdi'",
    ] {
        never(text, Reason::ServerFileOrOsAccess);
    }
}

/// Hazard: lexer settings change meaning (§4.3). `sql_mode` and the client
/// character set are pinned for the session: any statement that changes
/// them never runs, however the value is written.
#[test]
fn hazard_lexer_setting_changes() {
    for text in [
        "SET sql_mode = 'ANSI_QUOTES'",
        "SET SESSION sql_mode = ''",
        "SET LOCAL sql_mode = DEFAULT",
        "SET @@sql_mode = 'NO_BACKSLASH_ESCAPES'",
        "SET @@session.sql_mode := CONCAT(@@sql_mode, ',ANSI_QUOTES')",
        "SET @@SESSION.SQL_MODE = 'ANSI'",
        "SET `sql_mode` = ''",
        "SET NAMES gbk",
        "SET NAMES 'sjis' COLLATE 'sjis_bin'",
        "SET CHARACTER SET big5",
        "SET CHARSET cp932",
        "SET character_set_client = 'gbk'",
        "SET collation_connection = 'gbk_bin'",
        "SET @x = 1, sql_mode = ''",
        "SET STATEMENT sql_mode = 'ANSI_QUOTES' FOR SELECT 1",
        "SET STATEMENT max_statement_time = 1 FOR SELECT 1",
    ] {
        never(text, Reason::LexerSettingChange);
    }
    // A global change does not reach this session: sql_admin.
    requires("SET GLOBAL sql_mode = ''", &["sql_admin server"]);
    requires("SET @@global.sql_mode = ''", &["sql_admin server"]);
    // Reading them is fine.
    requires("SELECT @@sql_mode, @@character_set_client", &["sql_select server"]);
}

/// Hazard: the read-only guard (§5.3). Nothing lifts `READ ONLY`.
#[test]
fn hazard_read_only_guard() {
    for text in [
        "SET SESSION TRANSACTION READ WRITE",
        "SET TRANSACTION READ WRITE",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ WRITE",
        "START TRANSACTION READ WRITE",
        "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ WRITE",
        "SET transaction_read_only = 0",
        "SET SESSION transaction_read_only = OFF",
        "SET @@session.tx_read_only = OFF",
        "SET @@transaction_read_only := 0",
    ] {
        never(text, Reason::ReadOnlyGuardChange);
    }
    tx("START TRANSACTION READ ONLY", StatementKind::TxBegin);
    requires("SET SESSION TRANSACTION READ ONLY", &["sql_select server"]);
    requires("SET TRANSACTION ISOLATION LEVEL READ COMMITTED", &["sql_select server"]);
}

/// Hazard: `sql_mode` changes where literals end. The same text under the
/// session's modes: what the parser cannot read the server's way is
/// refused, and the split always follows the server.
#[test]
fn lexer_settings_the_same_text_under_different_sql_modes() {
    let dq = "SELECT \"a\" FROM t";
    requires(dq, &["sql_select rel:app.t"]);
    refused_with(Dialect::MySql, st(true, false), dq, Reason::LexerSettingUnsupported, Refusal::Unknown);
    let bs = "SELECT 'a\\b' FROM t";
    requires(bs, &["sql_select rel:app.t"]);
    refused_with(Dialect::MySql, st(false, true), bs, Reason::LexerSettingUnsupported, Refusal::Unknown);
    // Backticks read the same under every mode.
    for s in [st(false, false), st(true, false), st(false, true), st(true, true)] {
        let c = one_with(Dialect::MySql, s, "SELECT `a` FROM `t`", &ctx());
        assert_eq!(render(&c), BTreeSet::from(["sql_select rel:app.t".to_string()]));
    }
}

/// Hazard: a built-in written with a space before `(` may resolve to a
/// stored function of the same name (no `IGNORE_SPACE`).
#[test]
fn hazard_space_before_builtin_parenthesis() {
    for text in ["SELECT SUM (a) FROM t", "SELECT count/**/(*) FROM t", "SELECT max\n(a) FROM t"] {
        refused(text, Reason::SpaceBeforeParenthesis, Refusal::Unknown);
    }
    requires("SELECT SUM(a), count(*) FROM t", &["sql_select rel:app.t"]);
    // Not in sql_functions[]: whitespace does not matter to the server.
    requires("SELECT abs (a) FROM t", &["sql_select rel:app.t"]);
    // Qualified, it is a stored function either way.
    let s = requires("SELECT app.sum (a) FROM t", &["sql_execute fn:app.sum", "sql_select rel:app.t"]);
    assert!(s.opaque);
}

/// Hazard: side-effecting functions inside `SELECT` (§4.3 function table).
#[test]
fn hazard_side_effecting_functions() {
    let s = requires("SELECT my_udf(a) FROM t", &["sql_execute server", "sql_select rel:app.t"]);
    assert!(s.opaque);
    requires("SELECT app.f(1)", &["sql_execute fn:app.f"]);
    requires("SELECT GET_LOCK('k', 1)", &["sql_update server"]);
    requires("SELECT RELEASE_LOCK('k')", &["sql_update server"]);
    requires("SELECT IS_FREE_LOCK('k')", &["sql_select server"]);
    requires("SELECT MASTER_POS_WAIT('f', 4)", &["sql_admin server"]);
    requires("SELECT row_number() OVER (ORDER BY a) FROM t", &["sql_select rel:app.t"]);
    requires("SELECT row_number() FROM t", &["sql_execute server", "sql_select rel:app.t"]);
    // In a session the database keeps read-only, a stored function needs
    // only sql_select on it; a loadable (native) one never downgrades.
    let ro = NameContext { database_read_only: true, ..ctx() };
    requires_with(Dialect::MySql, &ro, "SELECT app.f(1)", &["sql_select fn:app.f"]);
    requires_with(Dialect::MySql, &ro, "SELECT my_udf(1)", &["sql_execute server"]);
    // MariaDB sequences; on MySQL the same names are user code.
    requires_with(Dialect::MariaDb, &ctx(), "SELECT nextval(s)", &["sql_update seq:app.s"]);
    requires_with(Dialect::MariaDb, &ctx(), "SELECT setval(db2.s, 10)", &["sql_update seq:db2.s"]);
    requires_with(Dialect::MariaDb, &ctx(), "SELECT lastval(s)", &["sql_select seq:app.s"]);
    requires_with(Dialect::MySql, &ctx(), "SELECT nextval(s)", &["sql_execute server"]);
    // Built-ins of one flavor only.
    requires_with(Dialect::MySql, &ctx(), "SELECT regexp_like(a, 'x') FROM t", &["sql_select rel:app.t"]);
    requires_with(
        Dialect::MariaDb,
        &ctx(),
        "SELECT regexp_like(a, 'x') FROM t",
        &["sql_execute server", "sql_select rel:app.t"],
    );
}

/// Hazard: `EXPLAIN ANALYZE` executes.
#[test]
fn hazard_explain_analyze_executes() {
    let s = requires("EXPLAIN ANALYZE SELECT * FROM t", &["sql_select rel:app.t"]);
    assert_eq!(s.kind, StatementKind::ExplainAnalyze);
    let s = requires("EXPLAIN DELETE FROM t WHERE a = 1", &["sql_select rel:app.t"]);
    assert_eq!(s.kind, StatementKind::Explain);
    // MariaDB's `ANALYZE <statement>` runs it too: not classified.
    refused_with(
        Dialect::MariaDb,
        st(false, false),
        "ANALYZE DELETE FROM t",
        Reason::UnsupportedStatement,
        Refusal::Unknown,
    );
}

/// An `Unknown` refusal that names a pinned setting or the guard is raised
/// to `Never`, so `sql_admin` cannot run it as `unclassified` either.
#[test]
fn unknown_refusals_naming_the_guards_never_run() {
    for text in ["HANDLER t OPEN AS sql_mode", "XA START 'x' tx_read_only", "DO 1 + transaction_read_only"] {
        let u = run(text).unwrap_err();
        assert_eq!(u.refusal, Refusal::Never, "{text:?}: {u:?}");
    }
    unknown("HANDLER t OPEN");
}

// ---------------------------------------------------------------------------
// §4.2 statement table.
// ---------------------------------------------------------------------------

#[test]
fn queries() {
    requires("SELECT a FROM t", &["sql_select rel:app.t"]);
    requires("SELECT 1", &["sql_select server"]);
    requires("SELECT * FROM db2.u JOIN t ON t.id = u.id", &["sql_select rel:db2.u", "sql_select rel:app.t"]);
    requires("SELECT * FROM t WHERE a IN (SELECT b FROM u)", &["sql_select rel:app.t", "sql_select rel:app.u"]);
    requires("SELECT * FROM t FOR UPDATE", &["sql_select rel:app.t", "sql_update rel:app.t"]);
    requires("SELECT * FROM t FOR SHARE", &["sql_select rel:app.t", "sql_update rel:app.t"]);
    // sqlparser does not read the pre-8.0 spelling: not classified.
    unknown("SELECT * FROM t LOCK IN SHARE MODE");
    requires("WITH c AS (SELECT * FROM t) SELECT * FROM c", &["sql_select rel:app.t"]);
    requires(
        "WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT * FROM r",
        &["sql_select server"],
    );
    requires("SELECT a INTO @v FROM t LIMIT 1", &["sql_select rel:app.t"]);
    requires("SELECT * FROM t USE INDEX (i) WHERE a = 1", &["sql_select rel:app.t"]);
    requires("SELECT JSON_EXTRACT(j, '$.a'), j->'$.b' FROM t", &["sql_select rel:app.t"]);
    requires("SELECT * FROM t WHERE MATCH (a) AGAINST ('x')", &["sql_select rel:app.t"]);
    requires("SELECT _utf8mb4'x' COLLATE utf8mb4_bin", &["sql_select server"]);
    unknown("SELECT ?");
}

#[test]
fn writes() {
    requires("INSERT INTO t (a) VALUES (1)", &["sql_insert rel:app.t"]);
    requires("INSERT INTO t SET a = 1", &["sql_insert rel:app.t"]);
    requires("INSERT IGNORE INTO t VALUES (1)", &["sql_insert rel:app.t"]);
    requires("INSERT INTO t SELECT * FROM u", &["sql_insert rel:app.t", "sql_select rel:app.u"]);
    requires("REPLACE INTO t VALUES (1)", &["sql_insert rel:app.t", "sql_delete rel:app.t"]);
    requires(
        "INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE a = VALUES(a)",
        &["sql_insert rel:app.t", "sql_select rel:app.t", "sql_update rel:app.t"],
    );
    requires("UPDATE t SET a = 1", &["sql_update rel:app.t"]);
    requires("UPDATE t SET a = 1 WHERE id = 2", &["sql_update rel:app.t", "sql_select rel:app.t"]);
    requires("UPDATE t SET a = 1 ORDER BY id LIMIT 1", &["sql_update rel:app.t", "sql_select rel:app.t"]);
    requires(
        "UPDATE t SET a = (SELECT max(b) FROM u)",
        &["sql_update rel:app.t", "sql_select rel:app.t", "sql_select rel:app.u"],
    );
    requires(
        "UPDATE t JOIN u ON t.id = u.id SET t.a = u.b",
        &["sql_update rel:app.t", "sql_select rel:app.t", "sql_update rel:app.u", "sql_select rel:app.u"],
    );
    requires("DELETE FROM t", &["sql_delete rel:app.t"]);
    requires("DELETE FROM t WHERE id = 1", &["sql_delete rel:app.t", "sql_select rel:app.t"]);
    requires(
        "DELETE t FROM t JOIN u ON t.id = u.id",
        &["sql_delete rel:app.t", "sql_select rel:app.t", "sql_delete rel:app.u", "sql_select rel:app.u"],
    );
    requires(
        "DELETE a FROM t AS a JOIN db2.u b ON a.id = b.id WHERE b.x = 1",
        &["sql_delete rel:app.t", "sql_select rel:app.t", "sql_delete rel:db2.u", "sql_select rel:db2.u"],
    );
}

#[test]
fn ddl_and_maintenance() {
    requires(
        "CREATE TABLE n (id int PRIMARY KEY, u_id int REFERENCES u (id))",
        &["sql_create rel:app.n", "sql_alter rel:app.u"],
    );
    requires(
        "CREATE TABLE n AS SELECT * FROM t",
        &["sql_create rel:app.n", "sql_insert rel:app.n", "sql_select rel:app.t"],
    );
    requires("CREATE TABLE n LIKE t", &["sql_create rel:app.n", "sql_select rel:app.t"]);
    requires("CREATE TEMPORARY TABLE n (a int) ENGINE=InnoDB", &["sql_create rel:app.n"]);
    requires("CREATE VIEW v AS SELECT * FROM t", &["sql_create rel:app.v", "sql_select rel:app.t"]);
    requires("CREATE OR REPLACE VIEW v AS SELECT 1", &["sql_create rel:app.v", "sql_alter rel:app.v"]);
    requires("CREATE INDEX i ON t (a)", &["sql_create rel:app.t"]);
    requires("ALTER TABLE t ADD COLUMN b int", &["sql_alter rel:app.t"]);
    requires("ALTER TABLE t RENAME TO t2", &["sql_alter rel:app.t", "sql_create rel:app.t2"]);
    requires("DROP TABLE t, db2.u", &["sql_drop rel:app.t", "sql_drop rel:db2.u"]);
    requires("DROP TEMPORARY TABLE IF EXISTS t", &["sql_drop rel:app.t"]);
    requires("DROP VIEW v", &["sql_drop rel:app.v"]);
    requires("DROP INDEX i ON t", &["sql_drop rel:app.t"]);
    requires("DROP PROCEDURE IF EXISTS p", &["sql_drop fn:app.p"]);
    requires("DROP FUNCTION db2.F", &["sql_drop fn:db2.f"]);
    requires("DROP TRIGGER tr", &["sql_drop server"]);
    requires("TRUNCATE TABLE t", &["sql_drop rel:app.t"]);
    requires("TRUNCATE t", &["sql_drop rel:app.t"]);
    requires(
        "RENAME TABLE t TO t2, u TO db2.u",
        &["sql_alter rel:app.t", "sql_create rel:app.t2", "sql_alter rel:app.u", "sql_create rel:db2.u"],
    );
    let s = requires("CREATE PROCEDURE p() SELECT 1", &["sql_create fn:app.p"]);
    assert_eq!(s.kind, StatementKind::CreateRoutine);
    requires("CREATE DEFINER = 'root'@'%' PROCEDURE p() SELECT 1", &["sql_create fn:app.p", "sql_admin server"]);
    requires("CREATE FUNCTION f(x int) RETURNS int DETERMINISTIC RETURN x + 1", &["sql_create fn:app.f"]);
    let s = requires(
        "CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW SET NEW.a = 1",
        &["sql_create rel:app.t", "sql_execute server"],
    );
    assert!(s.opaque);
    requires("ALTER PROCEDURE p COMMENT 'x'", &["sql_alter fn:app.p"]);
    requires("OPTIMIZE TABLE t", &["sql_alter rel:app.t"]);
    requires("ANALYZE TABLE t, u", &["sql_alter rel:app.t", "sql_alter rel:app.u"]);
    requires("REPAIR NO_WRITE_TO_BINLOG TABLE t QUICK", &["sql_alter rel:app.t"]);
    requires("CHECK TABLE t", &["sql_select rel:app.t"]);
    requires("CHECKSUM TABLE t EXTENDED", &["sql_select rel:app.t"]);
    requires_with(Dialect::MariaDb, &ctx(), "CREATE SEQUENCE s", &["sql_create seq:app.s"]);
    requires_with(Dialect::MariaDb, &ctx(), "DROP SEQUENCE s", &["sql_drop seq:app.s"]);
    // Compound statements are split; no piece passes as a definition.
    for text in [
        "CREATE PROCEDURE p() BEGIN SELECT 1; END",
        "CREATE TRIGGER tr AFTER DELETE ON t FOR EACH ROW BEGIN DELETE FROM u; END",
    ] {
        let each = classify_each(Dialect::MySql, st(false, false), text, &ctx()).unwrap();
        assert!(each.iter().all(|r| r.is_err()), "{text:?}: {each:?}");
    }
}

#[test]
fn admin_statements() {
    for text in [
        "GRANT SELECT ON *.* TO 'x'@'%'",
        "REVOKE ALL ON db.* FROM x",
        "CREATE USER 'x'@'%' IDENTIFIED BY 'pw'",
        "ALTER USER x IDENTIFIED BY 'pw'",
        "DROP USER x",
        "RENAME USER a TO b",
        "CREATE DATABASE d",
        "CREATE SCHEMA d",
        "DROP DATABASE d",
        "ALTER DATABASE d CHARACTER SET utf8mb4",
        "CREATE ROLE r",
        "SET ROLE r",
        "SET DEFAULT ROLE ALL TO x",
        "SET PASSWORD = 'pw'",
        "KILL 5",
        "KILL QUERY 5",
        "FLUSH PRIVILEGES",
        "RESET MASTER",
        "PURGE BINARY LOGS TO 'x'",
        "SHUTDOWN",
        "CHANGE REPLICATION SOURCE TO SOURCE_HOST = 'h'",
        "START REPLICA",
        "STOP SLAVE",
        "CREATE EVENT e ON SCHEDULE EVERY 1 HOUR DO DELETE FROM t",
        "LOCK INSTANCE FOR BACKUP",
        "SET GLOBAL max_connections = 10",
        "SET autocommit = 0",
        "SET foreign_key_checks = 0",
        "SHOW PROCESSLIST",
        "SHOW FULL PROCESSLIST",
        "SHOW ENGINE INNODB STATUS",
        "SHOW BINARY LOGS",
        "SHOW GRANTS FOR 'root'@'%'",
    ] {
        let s = one_with(Dialect::MySql, st(false, false), text, &ctx());
        assert!(render(&s).contains("sql_admin server"), "{text:?}: {s:?}");
    }
}

#[test]
fn show_describe_use() {
    requires("SHOW TABLES", &["sql_select server"]);
    requires("SHOW FULL TABLES FROM db2 LIKE 'a%'", &["sql_select server"]);
    requires("SHOW COLUMNS FROM t", &["sql_select rel:app.t"]);
    requires("SHOW FULL COLUMNS FROM t FROM db2", &["sql_select rel:db2.t"]);
    requires("SHOW INDEX FROM db2.t", &["sql_select rel:db2.t"]);
    requires("SHOW CREATE TABLE t", &["sql_select rel:app.t"]);
    requires("SHOW CREATE PROCEDURE p", &["sql_select fn:app.p"]);
    requires("SHOW DATABASES", &["sql_select server"]);
    requires("SHOW SESSION VARIABLES LIKE 'sql_mode'", &["sql_select server"]);
    requires("SHOW WARNINGS LIMIT 10", &["sql_select server"]);
    requires("SHOW GRANTS", &["sql_select server"]);
    requires("SHOW GRANTS FOR CURRENT_USER()", &["sql_select server"]);
    requires("DESCRIBE t", &["sql_select rel:app.t"]);
    requires("DESC db2.t a", &["sql_select rel:db2.t"]);
    requires("EXPLAIN t", &["sql_select rel:app.t"]);
    let s = requires("USE db2", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::SetSession);
    // A WHERE in SHOW could read any table: not classified.
    unknown("SHOW TABLES WHERE (SELECT 1) = 1");
    unknown("SHOW COUNT(*) WARNINGS");
}

#[test]
fn transactions_and_session_state() {
    tx("BEGIN", StatementKind::TxBegin);
    tx("BEGIN WORK", StatementKind::TxBegin);
    tx("START TRANSACTION", StatementKind::TxBegin);
    tx("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY", StatementKind::TxBegin);
    tx("COMMIT", StatementKind::TxCommit);
    tx("COMMIT WORK", StatementKind::TxCommit);
    tx("ROLLBACK", StatementKind::TxRollback);
    tx("SAVEPOINT s", StatementKind::TxSavepoint);
    tx("ROLLBACK TO SAVEPOINT s", StatementKind::TxSavepoint);
    tx("ROLLBACK WORK TO s", StatementKind::TxSavepoint);
    tx("RELEASE SAVEPOINT s", StatementKind::TxReleaseSavepoint);
    unknown("COMMIT AND CHAIN");
    unknown("COMMIT RELEASE");
    requires("SET @x = 1", &["sql_select server"]);
    requires("SET @x := 'a', @y = 2", &["sql_select server"]);
    requires("SET @x = (SELECT a FROM t LIMIT 1)", &["sql_select server", "sql_select rel:app.t"]);
    requires("SET time_zone = '+00:00'", &["sql_select server"]);
    requires("SET SESSION group_concat_max_len = 100000", &["sql_select server"]);
    let s = requires("SET @@session.time_zone = 'UTC'", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::SetSession);
    // A system variable with an expression is not read.
    unknown("SET time_zone = CONCAT('+0', '0:00')");
    let s = requires("PREPARE s FROM 'DELETE FROM t'", &["sql_execute server"]);
    assert!(s.opaque);
    requires("EXECUTE s USING @a, @b", &["sql_execute server"]);
    requires("DEALLOCATE PREPARE s", &["sql_select server"]);
    let s = requires("CALL p(1)", &["sql_execute fn:app.p"]);
    assert!(s.opaque && s.kind == StatementKind::Call);
    requires("CALL db2.P()", &["sql_execute fn:db2.p"]);
    requires("CALL p((SELECT a FROM t LIMIT 1))", &["sql_execute fn:app.p", "sql_select rel:app.t"]);
    requires(
        "LOCK TABLES t READ, u AS x WRITE",
        &["sql_select rel:app.t", "sql_select rel:app.u", "sql_update rel:app.u"],
    );
    requires("UNLOCK TABLES", &["sql_select server"]);
}

#[test]
fn names_follow_lower_case_table_names_and_the_current_database() {
    let fold = LexerSettings::MySql { ansi_quotes: false, no_backslash_escapes: false, fold_table_names: true };
    let s = one_with(Dialect::MySql, fold, "SELECT * FROM App.Users", &ctx());
    assert_eq!(render(&s), BTreeSet::from(["sql_select rel:app.users".to_string()]));
    requires("SELECT * FROM App.Users", &["sql_select rel:App.Users"]);
    // Quoting does not change case in MySQL.
    requires("SELECT * FROM `App`.`Users`", &["sql_select rel:App.Users"]);
    let none = NameContext::mysql(None);
    match run_with(Dialect::MySql, st(false, false), "SELECT * FROM t", &none) {
        Err(u) => assert_eq!((u.reason, u.refusal), (Reason::UnresolvableName, Refusal::Unknown)),
        other => panic!("{other:?}"),
    }
    requires_with(Dialect::MySql, &none, "SELECT * FROM db.t", &["sql_select rel:db.t"]);
    refused("TRUNCATE TABLE select", Reason::ReservedWordAsName, Refusal::Unknown);
    requires("TRUNCATE TABLE `select`", &["sql_drop rel:app.select"]);
}

#[test]
fn dialect_and_settings_must_match() {
    let pg = LexerSettings::PostgreSql { standard_conforming_strings: true };
    for (d, s) in [(Dialect::MySql, pg), (Dialect::MariaDb, pg), (Dialect::PostgreSql, st(false, false))] {
        let u = classify(d, s, "SELECT 1", &ctx()).unwrap_err();
        assert_eq!((u.reason, u.refusal), (Reason::DialectMismatch, Refusal::Never));
        assert_eq!(redact(d, s, "SELECT 1").unwrap_err().reason, Reason::DialectMismatch);
    }
}

#[test]
fn redaction_removes_literals_and_every_comment() {
    let text = "UPDATE `Users` SET email = 'ana@example.com', n = 42, b = \"x\\\"y\", h = X'ff' \
                /*! secret1 */ /* pw=hunter2 */ WHERE id = 7 # 0123\n -- tail 9876\n";
    let out = redact(Dialect::MySql, st(false, false), text).unwrap();
    for leaked in ["ana@example.com", "42", "x\\\"y", "ff", "secret1", "hunter2", "0123", "9876", "7"] {
        assert!(!out.contains(leaked), "{leaked} in {out}");
    }
    assert!(out.contains("`Users`") && out.contains("email = ?"), "{out}");
    // Where a literal ends follows NO_BACKSLASH_ESCAPES.
    let out = redact(Dialect::MySql, st(false, true), "SELECT 'a\\' OR b #'").unwrap();
    assert!(out.contains("OR b"), "{out}");
    let out = redact(Dialect::MySql, st(false, false), "SELECT 'a\\' OR b #'").unwrap();
    assert!(!out.contains("OR b"), "{out}");
    assert!(redact(Dialect::MySql, st(false, false), "SELECT 'unterminated").is_err());
}

// ---------------------------------------------------------------------------
// Malformed input.
// ---------------------------------------------------------------------------

#[test]
fn malformed_input_corpus() {
    for (text, reason) in [
        ("SELECT 'abc", Reason::UnterminatedLiteral),
        ("SELECT \"abc", Reason::UnterminatedLiteral),
        ("SELECT `abc", Reason::UnterminatedLiteral),
        ("SELECT /* abc", Reason::UnterminatedLiteral),
        ("SELECT x'ab", Reason::UnterminatedLiteral),
        ("SELECT 1\0", Reason::ControlCharacter),
        ("SELECT\u{0b}1", Reason::ControlCharacter),
        ("SELECT\u{7f}1", Reason::ControlCharacter),
        ("SELECT 1 \\ 2", Reason::InvalidCharacter),
        ("SELECT \\N", Reason::InvalidCharacter),
        ("SELECT 2fa FROM t", Reason::InvalidCharacter),
        ("SELECT\u{a0}1", Reason::InvalidCharacter),
        ("SELECT 1 /* /* */ */", Reason::ExecutableComment),
    ] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.statement_index), (reason, Refusal::Never, None), "{text:?}");
    }
    let deep = format!("SELECT {}1{}", "(".repeat(40), ")".repeat(40));
    let u = run(&deep).unwrap_err();
    assert_eq!(u.reason, Reason::NestingTooDeep);
    let big = "SELECT 1;".repeat(MAX_TEXT_BYTES / 9 + 1);
    assert_eq!(run(&big).unwrap_err().reason, Reason::InputTooLarge);
    // Parser-level garbage is refused per statement, with a span.
    for text in ["SELEC 1", "SELECT FROM WHERE", "INSERT INTO", "UPDATE SET", "))((", "SELECT 1 +", "@@", "`a`.`b`."] {
        if let Err(u) = run(text) {
            assert!(u.span.is_some() || u.refusal == Refusal::Never, "{text:?}: {u:?}");
        }
    }
    assert!(run("").unwrap().is_empty());
    assert!(run("  ; ;# c\n").unwrap().is_empty());
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
                assert!(!body.contains(';') || body.contains(['\'', '"', '`', '#', '-', '/']), "{body:?}");
                assert!(s.required.windows(2).all(|w| w[0] < w[1]), "sorted and deduplicated");
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

    fn cases() -> u32 {
        std::env::var("BV_SQL_CLASSIFY_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000)
    }

    const FRAGMENTS: &[&str] = &[
        "SELECT",
        "INSERT",
        "INTO",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "FROM",
        "WHERE",
        "WITH",
        "AS",
        "SET",
        "VALUES",
        "CREATE",
        "TABLE",
        "DROP",
        "ALTER",
        "BEGIN",
        "COMMIT",
        "START",
        "TRANSACTION",
        "READ",
        "WRITE",
        "ONLY",
        "SHOW",
        "TABLES",
        "DESCRIBE",
        "USE",
        "LOAD",
        "DATA",
        "LOCAL",
        "INFILE",
        "OUTFILE",
        "EXPLAIN",
        "ANALYZE",
        "FOR",
        "LOCK",
        "UNLOCK",
        "GRANT",
        "CALL",
        "EXECUTE",
        "PREPARE",
        "TRUNCATE",
        "ON",
        "DUPLICATE",
        "KEY",
        "SESSION",
        "GLOBAL",
        "NAMES",
        "STATEMENT",
        "sql_mode",
        "transaction_read_only",
        "t",
        "u",
        "db.t",
        "`T`",
        "`a``b`",
        "@x",
        "@@sql_mode",
        "@@session.time_zone",
        "load_file('x')",
        "f(1)",
        "count(*)",
        "sum (a)",
        "nextval(s)",
        "1",
        "0x1F",
        "0b01",
        "1e5",
        ".5",
        "'a'",
        "'a''b'",
        "'a\\'b'",
        "\"d\"",
        "X'1F'",
        "B'01'",
        "N'n'",
        "_utf8mb4'x'",
        "# c\n",
        "-- c\n",
        "--x",
        "/* c */",
        "/*! 1 */",
        "/*M! 2 */",
        "/*+ h */",
        ";",
        ",",
        "(",
        ")",
        "*",
        "=",
        ":=",
        "+",
        "-",
        "||",
        ".",
        " ",
        "\n",
        "\r",
        "\t",
        "'",
        "\"",
        "`",
        "\\",
        "/*",
        "?",
        "{",
        "}",
    ];

    fn soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.join(" "))
    }

    fn glued_soup() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(FRAGMENTS), 0..40).prop_map(|v| v.concat())
    }

    /// Fragments without a backslash or a double quote.
    fn plain_soup() -> impl Strategy<Value = String> {
        let fragments: Vec<&str> = FRAGMENTS.iter().copied().filter(|f| !f.contains(['\\', '"'])).collect();
        prop::collection::vec(prop::sample::select(fragments), 0..40).prop_map(|v| v.concat())
    }

    fn settings() -> impl Strategy<Value = LexerSettings> {
        (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(a, b, c)| LexerSettings::MySql {
            ansi_quotes: a,
            no_backslash_escapes: b,
            fold_table_names: c,
        })
    }

    fn dialect() -> impl Strategy<Value = Dialect> {
        prop::sample::select(&[Dialect::MySql, Dialect::MariaDb][..])
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_text_holds_the_invariants(text in any::<String>(), s in settings(), d in dialect()) {
            check_invariants(&text, &run_with(d, s, &text, &ctx()));
        }

        #[test]
        fn sql_soup_holds_the_invariants(text in soup(), s in settings(), d in dialect()) {
            check_invariants(&text, &run_with(d, s, &text, &ctx()));
        }

        #[test]
        fn glued_sql_soup_holds_the_invariants(text in glued_soup(), s in settings(), d in dialect()) {
            check_invariants(&text, &run_with(d, s, &text, &ctx()));
        }

        #[test]
        fn classification_is_deterministic(text in soup()) {
            prop_assert_eq!(run(&text), run(&text));
        }

        /// Without a backslash and a double quote, the lexer settings cannot
        /// change the result.
        #[test]
        fn settings_free_text_ignores_the_settings(text in plain_soup(), s in settings()) {
            let fold_free = LexerSettings::MySql { ansi_quotes: false, no_backslash_escapes: false, fold_table_names: false };
            let s = match s {
                LexerSettings::MySql { ansi_quotes, no_backslash_escapes, .. } =>
                    LexerSettings::MySql { ansi_quotes, no_backslash_escapes, fold_table_names: false },
                other => other,
            };
            prop_assert_eq!(run_with(Dialect::MySql, s, &text, &ctx()), run_with(Dialect::MySql, fold_free, &text, &ctx()));
        }

        /// Statements joined by `;` with comments between come back as
        /// exactly those statements.
        #[test]
        fn spans_are_the_statements(
            picks in prop::collection::vec(0usize..8, 1..12),
            seps in prop::collection::vec(prop::sample::select(&[";", " ; ", ";\n# c\n", "; /* x; */ ", ";;", ";\n-- c\n"][..]), 12),
        ) {
            const STATEMENTS: [&str; 8] = [
                "SELECT 1", "SELECT 'a;b' FROM t", "DELETE FROM t WHERE a = \"x;\"", "UPDATE t SET a = 1",
                "INSERT INTO t VALUES (';')", "BEGIN", "SELECT `x;` FROM u /* ; */ WHERE b = 2", "COMMIT",
            ];
            let mut text = String::new();
            for (i, p) in picks.iter().enumerate() {
                text.push_str(STATEMENTS[*p]);
                text.push_str(seps[i]);
            }
            let each = classify_each(Dialect::MySql, st(false, false), &text, &ctx()).unwrap();
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

/// Every multi-table write form checks every table it names for the write
/// (the targets may be aliases), or is not classified at all.
#[test]
fn multi_table_writes_are_conservative() {
    for (text, cap) in [
        ("UPDATE t, u SET t.a = u.b WHERE t.id = u.id", "sql_update"),
        ("UPDATE t AS x INNER JOIN u AS y ON x.id = y.id SET y.a = 1", "sql_update"),
        ("DELETE FROM t, u USING t JOIN u ON t.id = u.id", "sql_delete"),
        ("DELETE x, y FROM t AS x JOIN u AS y ON x.id = y.id", "sql_delete"),
    ] {
        match run(text) {
            Ok(v) => {
                let r = render(&v[0]);
                for table in ["rel:app.t", "rel:app.u"] {
                    assert!(r.contains(&format!("{cap} {table}")), "{text:?}: {r:?}");
                }
            }
            Err(u) => assert_eq!(u.refusal, Refusal::Unknown, "{text:?}: {u:?}"),
        }
    }
}
