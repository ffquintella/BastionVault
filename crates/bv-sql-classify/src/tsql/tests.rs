//! The T-SQL corpus (features/sql-browser.md Testing Plan, Classifier;
//! T128): every §4.3 hazard as a named test, the §4.2 statement table, the
//! session settings, a malformed-input corpus, then property tests over
//! generated input.

use std::collections::BTreeSet;

use crate::*;

fn ctx() -> NameContext {
    NameContext::mssql("app", Some("dbo".into()))
}

fn st(quoted_identifier: bool) -> LexerSettings {
    LexerSettings::MsSql {
        quoted_identifier,
        names: NameMatch::AsciiCaseInsensitive,
        catalogs: NameMatch::AsciiCaseInsensitive,
    }
}

fn run_with(s: LexerSettings, text: &str, ctx: &NameContext) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    classify(Dialect::MsSql, s, text, ctx)
}

fn run(text: &str) -> Result<Vec<ClassifiedStatement>, Unclassifiable> {
    run_with(st(true), text, &ctx())
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
fn one_with(s: LexerSettings, text: &str, ctx: &NameContext) -> ClassifiedStatement {
    match run_with(s, text, ctx) {
        Ok(mut v) if v.len() == 1 => v.remove(0),
        other => panic!("{text:?}: expected one classified statement, got {other:?}"),
    }
}

#[track_caller]
fn requires_with(ctx: &NameContext, text: &str, expected: &[&str]) -> ClassifiedStatement {
    let s = one_with(st(true), text, ctx);
    let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(render(&s), want, "{text:?}");
    s
}

#[track_caller]
fn requires(text: &str, expected: &[&str]) -> ClassifiedStatement {
    requires_with(&ctx(), text, expected)
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

#[track_caller]
fn unknown(text: &str) {
    match run(text) {
        Err(u) => assert_eq!(u.refusal, Refusal::Unknown, "{text:?}: {u:?}"),
        Ok(v) => panic!("{text:?}: expected an Unknown refusal, got {v:?}"),
    }
}

#[track_caller]
fn not_run(text: &str) {
    if let Ok(v) = run(text) {
        panic!("{text:?}: expected a refusal, got {v:?}");
    }
}

#[track_caller]
fn tx(text: &str, kind: StatementKind) {
    let s = one_with(st(true), text, &ctx());
    assert!(s.tx_control && s.required.is_empty(), "{text:?}: {s:?}");
    assert_eq!(s.kind, kind, "{text:?}");
}

// ---------------------------------------------------------------------------
// §4.3 hazards, one named test each.
// ---------------------------------------------------------------------------

/// Hazard: multi-statement smuggling. T-SQL needs no `;`, and SQL Server
/// runs a whole batch: a span holding two statements never runs, whatever
/// separates them.
#[test]
fn hazard_multi_statement_smuggling() {
    for text in [
        "SELECT 1 DELETE FROM t",
        "SELECT * FROM t\nDELETE FROM t",
        "SELECT * FROM t WHERE a = 1 UPDATE t SET a = 2",
        "SELECT a FROM t ORDER BY a INSERT INTO t VALUES (1)",
        "INSERT INTO t VALUES (1) DROP TABLE u",
        "UPDATE t SET a = 1 EXEC dbo.p",
    ] {
        never(text, Reason::NotOneStatement);
    }
    // A keyword the parser would take for an alias (`checkpoint`) is the
    // server's next statement: refused, never classified as one SELECT.
    for text in [
        "SELECT * FROM t checkpoint",
        "SELECT 1 AS shutdown",
        "SELECT * FROM t AS reconfigure",
        "SELECT * FROM t WAITFOR DELAY '0:0:5'",
        "INSERT INTO t VALUES (1) SELECT * FROM u",
        "SELECT 1 x DELETE FROM t",
        "SELECT * FROM t truncate TABLE u",
        "SELECT * FROM t revert",
        "SELECT * FROM t kill 52",
        "UPDATE TOP (1) t SET a = 1 DELETE FROM u",
    ] {
        not_run(text);
    }
    // Literals, brackets and comments hide `;` and statements alike.
    for text in [
        "SELECT 'x;DELETE FROM t'",
        "SELECT N'x; DELETE FROM t'",
        "SELECT [x;DELETE FROM t] FROM u",
        "SELECT \"x;DELETE FROM t\" FROM u",
        "SELECT 1 /* ; DELETE FROM t; /* nested */ still a comment; */",
        "SELECT 1 -- ; DELETE FROM t\n",
        "SELECT 1--1; DELETE FROM t\r\n",
    ] {
        let v = run(text).unwrap();
        assert_eq!(v.len(), 1, "{text:?}");
        assert!(render(&v[0]).iter().all(|r| !r.starts_with("sql_delete")), "{text:?}: {v:?}");
    }
    let text = "SELECT 1; DELETE FROM t";
    let v = run(text).unwrap();
    assert_eq!(v.iter().map(|s| &text[s.span.clone()]).collect::<Vec<_>>(), ["SELECT 1", "DELETE FROM t"]);
    assert_eq!(render(&v[1]), BTreeSet::from(["sql_delete rel:app.dbo.t".to_string()]));
    // No backslash escapes in T-SQL: this is two statements, the second
    // classified, never hidden.
    let v = run("SELECT 'a\\'; DELETE FROM t").unwrap();
    assert_eq!(v.len(), 2);
}

/// Hazard: `GO` is a client tool's batch separator, not T-SQL.
#[test]
fn hazard_go_batch_separator() {
    for text in ["SELECT 1\nGO\nDELETE FROM t", "SELECT 1\n  go 5\n", "GO"] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.span), (Reason::BatchSeparator, Refusal::Never, None), "{text:?}");
    }
    requires("SELECT go FROM t", &["sql_select rel:app.dbo.t"]);
}

/// Hazard: server file, OS, network and linked-server access. Always
/// refused; `sql_admin` does not unlock them (§4.2).
#[test]
fn hazard_file_os_and_remote_access() {
    for text in [
        "EXEC xp_cmdshell 'whoami'",
        "EXEC master..xp_cmdshell 'whoami'",
        "EXEC master.dbo.xp_dirtree 'C:\\'",
        "EXEC sp_OACreate 'WScript.Shell', @o OUT",
        "EXEC sp_execute_external_script @language = N'Python', @script = N'1'",
        "EXEC msdb.dbo.sp_send_dbmail @recipients = 'x@example.com'",
        "EXEC msdb.dbo.sp_start_job 'j'",
        "EXEC sp_addlinkedserver 'evil'",
        "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;', 'SELECT 1') AS r",
        "SELECT * FROM OPENROWSET(BULK 'C:\\x.txt', SINGLE_CLOB) AS r",
        "SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=x').db.dbo.t",
        "SELECT * FROM OPENQUERY(srv, 'SELECT 1')",
        "SELECT * FROM srv.db.dbo.t",
        "INSERT INTO t SELECT * FROM srv.db.dbo.u",
        "EXEC srv.db.dbo.p",
        "EXEC ('SELECT 1') AT srv",
        "BULK INSERT t FROM 'C:\\data.csv'",
        "BACKUP DATABASE app TO DISK = 'C:\\x.bak'",
        "RESTORE DATABASE app FROM DISK = 'C:\\x.bak'",
        "CREATE ASSEMBLY a FROM 'C:\\a.dll'",
        "CREATE EXTERNAL DATA SOURCE s WITH (LOCATION = 'x')",
        "SELECT * FROM sys.fn_get_audit_file('C:\\*.sqlaudit', DEFAULT, DEFAULT)",
        "CREATE SYNONYM s FOR srv.db.dbo.t",
        "SELECT * FROM t; EXEC xp_regread 'x'",
    ] {
        match run(text) {
            Err(u) => assert_eq!((u.reason, u.refusal), (Reason::ServerFileOrOsAccess, Refusal::Never), "{text:?}"),
            Ok(v) => panic!("{text:?}: {v:?}"),
        }
    }
    // An unread statement naming one is never run as `unclassified`.
    let u = run("SELEC xp_cmdshell").unwrap_err();
    assert_eq!(u.refusal, Refusal::Never);
}

/// Hazard: `QUOTED_IDENTIFIER` changes what `"…"` means (§4.3). Pinned:
/// any statement that changes it never runs.
#[test]
fn hazard_lexer_setting_changes() {
    for text in [
        "SET QUOTED_IDENTIFIER OFF",
        "SET QUOTED_IDENTIFIER ON",
        "set quoted_identifier off",
        "SET ANSI_DEFAULTS ON",
        "SET ANSI_NULLS, QUOTED_IDENTIFIER OFF",
        "SET NOCOUNT, ANSI_DEFAULTS ON",
    ] {
        never(text, Reason::LexerSettingChange);
    }
    // Reading it is fine.
    requires("SELECT SESSIONPROPERTY('QUOTED_IDENTIFIER')", &["sql_select server"]);
}

/// Hazard: the same text under both `QUOTED_IDENTIFIER` settings. What the
/// parser cannot read the server's way is refused; the split always follows
/// the server.
#[test]
fn lexer_settings_the_same_text_under_quoted_identifier() {
    requires("SELECT \"a\" FROM \"t\"", &["sql_select rel:app.dbo.t"]);
    match run_with(st(false), "SELECT \"a\" FROM t", &ctx()) {
        Err(u) => assert_eq!((u.reason, u.refusal), (Reason::LexerSettingUnsupported, Refusal::Unknown)),
        other => panic!("{other:?}"),
    }
    // Brackets read the same either way.
    for s in [st(true), st(false)] {
        let c = one_with(s, "SELECT [a] FROM [t]", &ctx());
        assert_eq!(render(&c), BTreeSet::from(["sql_select rel:app.dbo.t".to_string()]));
    }
}

/// Hazard: lock hints take locks a plain read does not (§4.2).
#[test]
fn hazard_lock_hints() {
    for hint in ["UPDLOCK", "XLOCK", "HOLDLOCK", "TABLOCKX", "SERIALIZABLE", "UPDLOCK, ROWLOCK"] {
        requires(
            &format!("SELECT * FROM t WITH ({hint}) WHERE a = 1"),
            &["sql_select rel:app.dbo.t", "sql_update rel:app.dbo.t"],
        );
    }
    requires("SELECT * FROM t WITH (NOLOCK)", &["sql_select rel:app.dbo.t"]);
    requires("SELECT * FROM t WITH (INDEX(ix), READPAST)", &["sql_select rel:app.dbo.t"]);
    requires(
        "SELECT * FROM t AS a WITH (NOLOCK) JOIN u AS b WITH (UPDLOCK) ON a.id = b.id",
        &["sql_select rel:app.dbo.t", "sql_select rel:app.dbo.u", "sql_update rel:app.dbo.u"],
    );
    // The legacy `t (NOLOCK)` form and unknown hints are not classified.
    unknown("SELECT * FROM t (NOLOCK)");
    unknown("SELECT * FROM t WITH (MYSTERYLOCK)");
}

/// Hazard: DML hidden in an `OUTPUT … INTO` clause.
#[test]
fn hazard_output_clause() {
    requires(
        "INSERT INTO t (a) OUTPUT inserted.a VALUES (1)",
        &["sql_insert rel:app.dbo.t", "sql_select rel:app.dbo.t"],
    );
    requires(
        "DELETE FROM t OUTPUT deleted.* INTO arch WHERE id = 1",
        &["sql_delete rel:app.dbo.t", "sql_select rel:app.dbo.t", "sql_insert rel:app.dbo.arch"],
    );
    requires(
        "INSERT INTO t OUTPUT inserted.a INTO hist.arch (a) VALUES (1)",
        &["sql_insert rel:app.dbo.t", "sql_select rel:app.dbo.t", "sql_insert rel:app.hist.arch"],
    );
    requires(
        "UPDATE t SET a = 1 OUTPUT deleted.a, inserted.a WHERE id = 2",
        &["sql_update rel:app.dbo.t", "sql_select rel:app.dbo.t"],
    );
    let s = requires(
        "MERGE t AS tgt USING s AS src ON tgt.id = src.id \
         WHEN MATCHED THEN UPDATE SET a = src.a WHEN NOT MATCHED THEN INSERT (id) VALUES (src.id) \
         OUTPUT $action, inserted.id INTO log",
        &[
            "sql_select rel:app.dbo.t",
            "sql_update rel:app.dbo.t",
            "sql_insert rel:app.dbo.t",
            "sql_select rel:app.dbo.s",
            "sql_insert rel:app.dbo.log",
        ],
    );
    assert_eq!(s.kind, StatementKind::Merge);
}

/// Hazard: `SELECT … INTO` creates and fills a table (§4.2).
#[test]
fn hazard_select_into() {
    let s = requires(
        "SELECT * INTO new_t FROM t WHERE a = 1",
        &["sql_create rel:app.dbo.new_t", "sql_insert rel:app.dbo.new_t", "sql_select rel:app.dbo.t"],
    );
    assert_eq!(s.kind, StatementKind::SelectInto);
    requires(
        "SELECT a INTO #tmp FROM t",
        &["sql_create rel:tempdb.dbo.#tmp", "sql_insert rel:tempdb.dbo.#tmp", "sql_select rel:app.dbo.t"],
    );
}

/// Hazard: data-modifying CTEs (§4.3): every statement node is classified,
/// and a write through a CTE (which reaches its base table) is refused.
#[test]
fn hazard_cte_dml() {
    requires(
        "WITH c AS (SELECT id FROM u) DELETE FROM t WHERE id IN (SELECT id FROM c)",
        &["sql_delete rel:app.dbo.t", "sql_select rel:app.dbo.t", "sql_select rel:app.dbo.u"],
    );
    for text in [
        "WITH c AS (SELECT * FROM t) DELETE FROM c",
        "WITH c AS (SELECT * FROM t) UPDATE c SET a = 1",
        "WITH c AS (SELECT * FROM t) INSERT INTO c (a) VALUES (1)",
    ] {
        unknown(text);
    }
    requires("WITH c AS (SELECT * FROM t) SELECT * FROM c", &["sql_select rel:app.dbo.t"]);
    // A CTE sees only the ones before it: `b` in `a` is the real table.
    requires("WITH a AS (SELECT * FROM b), b AS (SELECT 1 x) SELECT * FROM a, b", &["sql_select rel:app.dbo.b"]);
}

/// Hazard: dynamic SQL hides the real statement (§4.3): opaque, `sql_execute`
/// on the server; `EXECUTE AS` and `REVERT` are `sql_admin`.
#[test]
fn hazard_dynamic_sql_and_execute_as() {
    for text in [
        "EXEC ('DELETE FROM t')",
        "EXECUTE (@sql)",
        "EXEC (N'SELECT ' + @col + N' FROM t')",
        "EXEC sp_executesql N'SELECT 1'",
        "EXECUTE sys.sp_executesql @stmt, N'@p int', @p = 1",
        "EXEC @proc_name",
    ] {
        let s = requires(text, &["sql_execute server"]);
        assert!(s.opaque, "{text:?}");
    }
    requires("EXEC ('SELECT 1') AS USER = 'dbo'", &["sql_execute server", "sql_admin server"]);
    for text in ["EXECUTE AS USER = 'dbo'", "EXEC AS LOGIN = 'sa'", "EXECUTE AS CALLER", "REVERT"] {
        let s = requires(text, &["sql_admin server"]);
        assert!(s.opaque, "{text:?}");
    }
    // The procedure's own call.
    let s = requires("EXEC dbo.p 1, @x = 'a', @y = @v OUTPUT", &["sql_execute fn:app.dbo.p"]);
    assert!(s.opaque && s.kind == StatementKind::Call);
    requires("EXECUTE @rc = p DEFAULT", &["sql_execute fn:app.dbo.p"]);
    // System procedures are server code.
    requires("EXEC sp_configure 'show advanced options', 1", &["sql_admin server"]);
    requires("EXEC sys.sp_who", &["sql_admin server"]);
    // Parameters are constants only; anything after them is not read.
    unknown("EXEC dbo.p 1 DELETE FROM t");
    unknown("EXEC dbo.p (SELECT 1)");
}

/// Hazard: side-effecting functions (§4.3 function table).
#[test]
fn hazard_side_effecting_functions() {
    requires("SELECT GETDATE(), LEN(a), COALESCE(a, b) FROM t", &["sql_select rel:app.dbo.t"]);
    let s = requires("SELECT dbo.f(a) FROM t", &["sql_execute fn:app.dbo.f", "sql_select rel:app.dbo.t"]);
    assert!(s.opaque);
    requires("SELECT mystery_builtin(1)", &["sql_execute server"]);
    requires("SELECT row_number() OVER (ORDER BY a) FROM t", &["sql_select rel:app.dbo.t"]);
    requires("SELECT * FROM dbo.tvf(1) AS f", &["sql_execute fn:app.dbo.tvf", "sql_select fn:app.dbo.tvf"]);
    requires("SELECT value FROM STRING_SPLIT('a,b', ',')", &["sql_select server"]);
    requires(
        "SELECT * FROM t CROSS APPLY dbo.f(t.a) AS x",
        &["sql_select rel:app.dbo.t", "sql_execute fn:app.dbo.f", "sql_select fn:app.dbo.f"],
    );
}

/// An `Unknown` refusal that names a pinned setting is raised to `Never`.
#[test]
fn unknown_refusals_naming_the_guards_never_run() {
    for text in ["IF 1 = 1 SET QUOTED_IDENTIFIER OFF", "WHILE 1 = 0 SELECT ansi_defaults"] {
        let u = run(text).unwrap_err();
        assert_eq!(u.refusal, Refusal::Never, "{text:?}: {u:?}");
    }
    unknown("IF 1 = 1 SELECT 1");
}

// ---------------------------------------------------------------------------
// §4.2 statement table.
// ---------------------------------------------------------------------------

#[test]
fn queries() {
    requires("SELECT a FROM t", &["sql_select rel:app.dbo.t"]);
    requires("SELECT 1", &["sql_select server"]);
    requires("SELECT TOP 5 * FROM db2.sales.t ORDER BY 1", &["sql_select rel:db2.sales.t"]);
    requires(
        "SELECT * FROM t JOIN hr.u ON t.id = u.id WHERE a IN (SELECT b FROM v)",
        &["sql_select rel:app.dbo.t", "sql_select rel:app.hr.u", "sql_select rel:app.dbo.v"],
    );
    requires("SELECT a FROM t FOR JSON PATH", &["sql_select rel:app.dbo.t"]);
    requires("SELECT a FROM t FOR XML AUTO", &["sql_select rel:app.dbo.t"]);
    requires("SELECT a FROM t ORDER BY a OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY", &["sql_select rel:app.dbo.t"]);
    requires("SELECT @x = a FROM t", &["sql_select rel:app.dbo.t"]);
    requires("SELECT $12.50, 0x1F, N'é', @@ROWCOUNT", &["sql_select server"]);
    requires("SELECT * FROM #tmp", &["sql_select rel:tempdb.dbo.#tmp"]);
    requires("SELECT * FROM @tv", &["sql_select server"]);
    requires("SELECT * FROM db2..t", &["sql_select rel:db2.?.t"]);
    unknown("SELECT * FROM t FOR BROWSE");
    unknown("SELECT a FROM t OPTION (MAXDOP 1)");
}

#[test]
fn writes() {
    requires("INSERT INTO t (a) VALUES (1)", &["sql_insert rel:app.dbo.t"]);
    requires("INSERT t VALUES (1)", &["sql_insert rel:app.dbo.t"]);
    requires("INSERT INTO t DEFAULT VALUES", &["sql_insert rel:app.dbo.t"]);
    requires("INSERT INTO t SELECT * FROM u", &["sql_insert rel:app.dbo.t", "sql_select rel:app.dbo.u"]);
    requires("UPDATE t SET a = 1", &["sql_update rel:app.dbo.t"]);
    // sqlparser reads `TOP (5)` as a table function aliased `t`: refused.
    unknown("UPDATE TOP (5) t SET a = 1 WHERE b = 2");
    requires(
        "UPDATE x SET a = u.b FROM t AS x JOIN u ON x.id = u.id",
        &[
            "sql_update rel:app.dbo.t",
            "sql_select rel:app.dbo.t",
            "sql_update rel:app.dbo.u",
            "sql_select rel:app.dbo.u",
        ],
    );
    requires("DELETE FROM t", &["sql_delete rel:app.dbo.t"]);
    requires("DELETE FROM t WHERE id = 1", &["sql_delete rel:app.dbo.t", "sql_select rel:app.dbo.t"]);
    requires(
        "DELETE x FROM t AS x JOIN u ON x.id = u.id",
        &[
            "sql_delete rel:app.dbo.t",
            "sql_select rel:app.dbo.t",
            "sql_delete rel:app.dbo.u",
            "sql_select rel:app.dbo.u",
        ],
    );
    // A derived table in an UPDATE … FROM may be the target: not classified.
    unknown("UPDATE d SET a = 1 FROM (SELECT * FROM t) AS d");
    requires(
        "MERGE INTO t USING u ON t.id = u.id WHEN MATCHED THEN DELETE",
        &["sql_select rel:app.dbo.t", "sql_delete rel:app.dbo.t", "sql_select rel:app.dbo.u"],
    );
}

#[test]
fn ddl_and_maintenance() {
    requires(
        "CREATE TABLE n (id int IDENTITY(1,1) PRIMARY KEY, u_id int REFERENCES u (id))",
        &["sql_create rel:app.dbo.n", "sql_alter rel:app.dbo.u"],
    );
    requires("CREATE TABLE #t (a int)", &["sql_create rel:tempdb.dbo.#t"]);
    requires("CREATE VIEW v AS SELECT * FROM t", &["sql_create rel:app.dbo.v", "sql_select rel:app.dbo.t"]);
    requires("CREATE OR ALTER VIEW v AS SELECT 1 AS x", &["sql_create rel:app.dbo.v", "sql_alter rel:app.dbo.v"]);
    requires("CREATE INDEX i ON t (a) INCLUDE (b)", &["sql_create rel:app.dbo.t"]);
    requires("ALTER TABLE t ADD c int", &["sql_alter rel:app.dbo.t"]);
    requires("DROP TABLE IF EXISTS t, db2.dbo.u", &["sql_drop rel:app.dbo.t", "sql_drop rel:db2.dbo.u"]);
    requires("DROP VIEW v", &["sql_drop rel:app.dbo.v"]);
    requires("DROP INDEX i ON t", &["sql_drop rel:app.dbo.t"]);
    requires("DROP INDEX t.i", &["sql_drop rel:app.dbo.t"]);
    requires("DROP PROCEDURE IF EXISTS p", &["sql_drop fn:app.dbo.p"]);
    requires("DROP FUNCTION hr.F", &["sql_drop fn:app.hr.f"]);
    requires("DROP TRIGGER tr", &["sql_drop server"]);
    requires("DROP SEQUENCE s", &["sql_drop seq:app.dbo.s"]);
    requires("TRUNCATE TABLE t", &["sql_drop rel:app.dbo.t"]);
    let s = requires("CREATE PROCEDURE p AS SELECT * FROM t", &["sql_create fn:app.dbo.p"]);
    assert_eq!(s.kind, StatementKind::CreateRoutine);
    requires(
        "CREATE OR ALTER PROC p @a int AS BEGIN SELECT @a END",
        &["sql_create fn:app.dbo.p", "sql_alter fn:app.dbo.p"],
    );
    requires("CREATE PROCEDURE p WITH EXECUTE AS OWNER AS SELECT 1", &["sql_create fn:app.dbo.p", "sql_admin server"]);
    requires("ALTER FUNCTION dbo.f () RETURNS int AS BEGIN RETURN 1 END", &["sql_alter fn:app.dbo.f"]);
    let s = requires(
        "CREATE TRIGGER tr ON t AFTER INSERT AS UPDATE u SET a = 1",
        &["sql_create rel:app.dbo.t", "sql_execute server"],
    );
    assert!(s.opaque);
    requires("CREATE TRIGGER tr ON DATABASE FOR CREATE_TABLE AS PRINT 'x'", &["sql_admin server"]);
    requires("CREATE SEQUENCE s START WITH 1 INCREMENT BY 1", &["sql_create seq:app.dbo.s"]);
    requires("CREATE SYNONYM syn FOR dbo.t", &["sql_create rel:app.dbo.syn"]);
    requires("ALTER INDEX ALL ON t REBUILD", &["sql_alter rel:app.dbo.t"]);
    requires("ALTER INDEX i ON t SET (ALLOW_PAGE_LOCKS = ON)", &["sql_alter rel:app.dbo.t"]);
    requires("UPDATE STATISTICS t WITH FULLSCAN", &["sql_alter rel:app.dbo.t"]);
    requires("DISABLE TRIGGER tr ON t", &["sql_alter rel:app.dbo.t"]);
    requires("SET IDENTITY_INSERT t ON", &["sql_alter rel:app.dbo.t"]);
    // Option lists never hide a second statement.
    unknown("ALTER INDEX ALL ON t REBUILD DELETE FROM u");
    unknown("CREATE SEQUENCE s DELETE FROM u");
}

#[test]
fn admin_statements() {
    for text in [
        "GRANT SELECT ON t TO u",
        "DENY DELETE ON t TO u",
        "REVOKE ALL ON t FROM u",
        "CREATE LOGIN l WITH PASSWORD = 'x'",
        "ALTER LOGIN l DISABLE",
        "CREATE USER u FOR LOGIN l",
        "DROP USER u",
        "CREATE ROLE r",
        "ALTER ROLE db_owner ADD MEMBER u",
        "CREATE DATABASE d",
        "DROP DATABASE d",
        "ALTER DATABASE app SET RECOVERY SIMPLE",
        "CREATE SCHEMA s",
        "DROP SCHEMA s",
        "ALTER SCHEMA s TRANSFER dbo.t",
        "ALTER AUTHORIZATION ON SCHEMA::s TO u",
        "DBCC CHECKDB",
        "KILL 52",
        "SHUTDOWN WITH NOWAIT",
        "CHECKPOINT",
        "RECONFIGURE",
        "SET CONTEXT_INFO 0x01",
        "SET IMPLICIT_TRANSACTIONS ON",
        "SET SHOWPLAN_XML ON",
        "BEGIN DISTRIBUTED TRANSACTION",
        "RAISERROR('x', 10, 1) WITH LOG",
        "OPEN SYMMETRIC KEY k DECRYPTION BY CERTIFICATE c",
    ] {
        let s = one_with(st(true), text, &ctx());
        assert!(render(&s).contains("sql_admin server"), "{text:?}: {s:?}");
    }
}

#[test]
fn transactions_and_session_state() {
    tx("BEGIN TRAN", StatementKind::TxBegin);
    tx("BEGIN TRANSACTION t1", StatementKind::TxBegin);
    tx("BEGIN TRANSACTION t1 WITH MARK 'm'", StatementKind::TxBegin);
    tx("COMMIT", StatementKind::TxCommit);
    tx("COMMIT TRAN t1", StatementKind::TxCommit);
    tx("COMMIT TRANSACTION WITH (DELAYED_DURABILITY = ON)", StatementKind::TxCommit);
    tx("COMMIT WORK", StatementKind::TxCommit);
    tx("ROLLBACK", StatementKind::TxRollback);
    tx("ROLLBACK TRANSACTION", StatementKind::TxRollback);
    tx("ROLLBACK TRAN sp1", StatementKind::TxSavepoint);
    tx("SAVE TRANSACTION sp1", StatementKind::TxSavepoint);
    // Transaction control never carries another statement.
    unknown("BEGIN TRAN DELETE FROM t");
    unknown("COMMIT SELECT 1");
    unknown("BEGIN");
    unknown("BEGIN SELECT 1 END");
    unknown("BEGIN TRY SELECT 1 END TRY BEGIN CATCH END CATCH");
    for text in [
        "SET NOCOUNT ON",
        "SET XACT_ABORT ON",
        "SET DATEFORMAT ymd",
        "SET LANGUAGE us_english",
        "SET LOCK_TIMEOUT 1000",
        "SET DEADLOCK_PRIORITY -5",
        "SET ANSI_NULLS, ANSI_WARNINGS ON",
        "SET STATISTICS IO ON",
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "SET TRANSACTION ISOLATION LEVEL SNAPSHOT",
    ] {
        let s = requires(text, &["sql_select server"]);
        assert_eq!(s.kind, StatementKind::SetSession, "{text:?}");
    }
    unknown("SET NOCOUNT ON SELECT 1");
    requires("SET @x = (SELECT a FROM t)", &["sql_select server", "sql_select rel:app.dbo.t"]);
    let s = requires("USE db2", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::SetSession);
    let s = requires("DECLARE @x int = (SELECT max(a) FROM t)", &["sql_select rel:app.dbo.t"]);
    assert_eq!(s.kind, StatementKind::Declare);
    let s = requires("DECLARE c CURSOR FOR SELECT a FROM t", &["sql_select rel:app.dbo.t"]);
    assert_eq!(s.kind, StatementKind::DeclareCursor);
    requires("OPEN c", &["sql_select server"]);
    requires("FETCH NEXT FROM c INTO @a, @b", &["sql_select server"]);
    requires("CLOSE c", &["sql_select server"]);
    requires("DEALLOCATE c", &["sql_select server"]);
    let s = requires("WAITFOR DELAY '00:00:01'", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::WaitFor);
    let s = requires("PRINT 'x'", &["sql_select server"]);
    assert_eq!(s.kind, StatementKind::Message);
    requires("RAISERROR('x', 16, 1)", &["sql_select server"]);
    requires("THROW 50000, 'x', 1", &["sql_select server"]);
}

#[test]
fn names_follow_the_collation_and_the_default_schema() {
    requires("SELECT * FROM App.Sales.Users", &["sql_select rel:app.sales.users"]);
    let cs = LexerSettings::MsSql {
        quoted_identifier: true,
        names: NameMatch::AsciiCaseSensitive,
        catalogs: NameMatch::AsciiCaseInsensitive,
    };
    let s = one_with(cs, "SELECT * FROM App.Sales.Users", &ctx());
    assert_eq!(render(&s), BTreeSet::from(["sql_select rel:app.Sales.Users".to_string()]));
    // Non-ASCII under a non-binary collation is not guessed.
    match run("SELECT * FROM [Ação]") {
        Err(u) => assert_eq!((u.reason, u.refusal), (Reason::UnresolvableName, Refusal::Unknown)),
        other => panic!("{other:?}"),
    }
    let bin = LexerSettings::MsSql { quoted_identifier: true, names: NameMatch::Exact, catalogs: NameMatch::Exact };
    let s = one_with(bin, "SELECT * FROM [Ação]", &ctx());
    assert_eq!(render(&s), BTreeSet::from(["sql_select rel:app.dbo.Ação".to_string()]));
    // Default schema other than dbo: unqualified names go to the caller.
    let sales = NameContext::mssql("app", Some("sales".into()));
    requires_with(&sales, "SELECT * FROM t", &["sql_select rel:app.?.t"]);
    requires_with(&sales, "CREATE TABLE n (a int)", &["sql_create rel:app.sales.n"]);
    refused("TRUNCATE TABLE select", Reason::ReservedWordAsName, Refusal::Unknown);
    requires("TRUNCATE TABLE [select]", &["sql_drop rel:app.dbo.select"]);
}

#[test]
fn dialect_and_settings_must_match() {
    let pg = LexerSettings::PostgreSql { standard_conforming_strings: true };
    let my = LexerSettings::MySql { ansi_quotes: false, no_backslash_escapes: false, fold_table_names: false };
    for (d, s) in
        [(Dialect::MsSql, pg), (Dialect::MsSql, my), (Dialect::PostgreSql, st(true)), (Dialect::MySql, st(true))]
    {
        let u = classify(d, s, "SELECT 1", &ctx()).unwrap_err();
        assert_eq!((u.reason, u.refusal), (Reason::DialectMismatch, Refusal::Never));
        assert_eq!(redact(d, s, "SELECT 1").unwrap_err().reason, Reason::DialectMismatch);
    }
}

#[test]
fn redaction_removes_literals_and_every_comment() {
    let text = "UPDATE [Users] SET email = N'ana@example.com', n = 42, m = $9.99, b = 0xFF \
                /* pw=hunter2 /* nested secret1 */ */ WHERE id = 7 -- 0123\n";
    let out = redact(Dialect::MsSql, st(true), text).unwrap();
    for leaked in ["ana@example.com", "42", "9.99", "FF", "hunter2", "secret1", "0123", "7"] {
        assert!(!out.contains(leaked), "{leaked} in {out}");
    }
    assert!(out.contains("[Users]") && out.contains("email = ?"), "{out}");
    let out = redact(Dialect::MsSql, st(false), "SELECT \"secret\" FROM t").unwrap();
    assert!(!out.contains("secret"), "{out}");
    assert!(redact(Dialect::MsSql, st(true), "SELECT 'unterminated").is_err());
}

// ---------------------------------------------------------------------------
// Malformed input.
// ---------------------------------------------------------------------------

#[test]
fn malformed_input_corpus() {
    for (text, reason) in [
        ("SELECT 'abc", Reason::UnterminatedLiteral),
        ("SELECT [abc", Reason::UnterminatedLiteral),
        ("SELECT \"abc", Reason::UnterminatedLiteral),
        ("SELECT /* abc /* */", Reason::UnterminatedLiteral),
        ("SELECT 1\0", Reason::ControlCharacter),
        ("SELECT\u{0b}1", Reason::ControlCharacter),
        ("SELECT 1 -- x\rDELETE FROM t", Reason::ControlCharacter),
        ("SELECT 1 \\ 2", Reason::InvalidCharacter),
        ("SELECT 2fa FROM t", Reason::InvalidCharacter),
        ("SELECT 1e", Reason::InvalidCharacter),
        ("SELECT\u{a0}1", Reason::InvalidCharacter),
    ] {
        let u = run(text).unwrap_err();
        assert_eq!((u.reason, u.refusal, u.statement_index), (reason, Refusal::Never, None), "{text:?}");
    }
    // `x'1F'` is a word and a string to SQL Server, a hex literal to the parser.
    match run("SELECT x'1F'") {
        Err(u) => assert_eq!(u.reason, Reason::LexerDisagreement, "{u:?}"),
        other => panic!("{other:?}"),
    }
    let deep = format!("SELECT {}1{}", "(".repeat(40), ")".repeat(40));
    assert_eq!(run(&deep).unwrap_err().reason, Reason::NestingTooDeep);
    let big = "SELECT 1;".repeat(MAX_TEXT_BYTES / 9 + 1);
    assert_eq!(run(&big).unwrap_err().reason, Reason::InputTooLarge);
    for text in ["SELEC 1", "SELECT FROM WHERE", "INSERT INTO", "UPDATE SET", "))((", "SELECT 1 +", "@@", "[a].[b]."] {
        if let Err(u) = run(text) {
            assert!(u.span.is_some() || u.refusal == Refusal::Never, "{text:?}: {u:?}");
        }
    }
    assert!(run("").unwrap().is_empty());
    assert!(run("  ; ;-- c\n").unwrap().is_empty());
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
                assert!(!body.contains(';') || body.contains(['\'', '"', '[', '-', '/']), "{body:?}");
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
        "MERGE",
        "FROM",
        "WHERE",
        "WITH",
        "AS",
        "SET",
        "VALUES",
        "OUTPUT",
        "inserted.a",
        "CREATE",
        "TABLE",
        "PROC",
        "DROP",
        "ALTER",
        "BEGIN",
        "TRAN",
        "COMMIT",
        "ROLLBACK",
        "SAVE",
        "EXEC",
        "EXECUTE",
        "sp_executesql",
        "xp_cmdshell",
        "OPENROWSET",
        "BULK",
        "GO",
        "\nGO\n",
        "USE",
        "DECLARE",
        "PRINT",
        "WAITFOR",
        "DELAY",
        "TOP",
        "(5)",
        "UPDLOCK",
        "NOLOCK",
        "HOLDLOCK",
        "QUOTED_IDENTIFIER",
        "ON",
        "OFF",
        "REVERT",
        "USER",
        "t",
        "u",
        "dbo.t",
        "db.dbo.t",
        "srv.db.dbo.t",
        "#tmp",
        "@v",
        "@@ROWCOUNT",
        "[a]]b]",
        "[T]",
        "\"q\"",
        "dbo.f(1)",
        "GETDATE()",
        "count(*)",
        "1",
        "0x1F",
        "$5",
        "1e5",
        ".5",
        "'a'",
        "'a''b'",
        "N'n'",
        "-- c\n",
        "--x",
        "/* c */",
        "/* /* n */ */",
        ";",
        ",",
        "(",
        ")",
        "*",
        "=",
        "+",
        "-",
        ".",
        "..",
        " ",
        "\n",
        "\r\n",
        "\r",
        "\t",
        "'",
        "\"",
        "[",
        "]",
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

    /// Fragments without a double quote: QUOTED_IDENTIFIER cannot matter.
    fn plain_soup() -> impl Strategy<Value = String> {
        let fragments: Vec<&str> = FRAGMENTS.iter().copied().filter(|f| !f.contains('"')).collect();
        prop::collection::vec(prop::sample::select(fragments), 0..40).prop_map(|v| v.concat())
    }

    fn name_match() -> impl Strategy<Value = NameMatch> {
        prop::sample::select(&[NameMatch::Exact, NameMatch::AsciiCaseSensitive, NameMatch::AsciiCaseInsensitive][..])
    }

    fn settings() -> impl Strategy<Value = LexerSettings> {
        (any::<bool>(), name_match(), name_match()).prop_map(|(q, n, c)| LexerSettings::MsSql {
            quoted_identifier: q,
            names: n,
            catalogs: c,
        })
    }

    fn context() -> impl Strategy<Value = NameContext> {
        (any::<bool>(), any::<bool>()).prop_map(|(dbo, ro)| NameContext {
            database_read_only: ro,
            ..NameContext::mssql("app", Some(if dbo { "dbo" } else { "sales" }.to_string()))
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

        #[test]
        fn arbitrary_text_holds_the_invariants(text in any::<String>(), s in settings(), c in context()) {
            check_invariants(&text, &run_with(s, &text, &c));
        }

        #[test]
        fn sql_soup_holds_the_invariants(text in soup(), s in settings(), c in context()) {
            check_invariants(&text, &run_with(s, &text, &c));
        }

        #[test]
        fn glued_sql_soup_holds_the_invariants(text in glued_soup(), s in settings(), c in context()) {
            check_invariants(&text, &run_with(s, &text, &c));
        }

        #[test]
        fn classification_is_deterministic(text in soup()) {
            prop_assert_eq!(run(&text), run(&text));
        }

        /// Without a double quote, QUOTED_IDENTIFIER cannot change the result.
        #[test]
        fn quote_free_text_ignores_quoted_identifier(text in plain_soup()) {
            prop_assert_eq!(run_with(st(true), &text, &ctx()), run_with(st(false), &text, &ctx()));
        }

        /// Statements joined by `;` with comments between come back as
        /// exactly those statements.
        #[test]
        fn spans_are_the_statements(
            picks in prop::collection::vec(0usize..8, 1..12),
            seps in prop::collection::vec(prop::sample::select(&[";", " ; ", ";\n-- c\n", "; /* x; */ ", ";;", "; /* a /* b; */ */\r\n"][..]), 12),
        ) {
            const STATEMENTS: [&str; 8] = [
                "SELECT 1", "SELECT 'a;b' FROM t", "DELETE FROM t WHERE a = N'x;'", "UPDATE t SET a = 1",
                "INSERT INTO t VALUES (';')", "BEGIN TRAN", "SELECT [x;] FROM u /* ; */ WHERE b = 2", "COMMIT",
            ];
            let mut text = String::new();
            for (i, p) in picks.iter().enumerate() {
                text.push_str(STATEMENTS[*p]);
                text.push_str(seps[i]);
            }
            let each = classify_each(Dialect::MsSql, st(true), &text, &ctx()).unwrap();
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
