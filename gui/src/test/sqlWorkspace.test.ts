import { describe, expect, it } from "vitest";

import type { SqlColumn, SqlDescribe } from "../lib/api";
import {
  buildDelete,
  buildInsert,
  buildUpdate,
  cellText,
  dangerousStatements,
  describeSqlError,
  editableKind,
  explainOf,
  formatSql,
  gridEditBlocker,
  isSessionGone,
  parsePluginError,
  quoteIdent,
  refusals,
  selectAllFrom,
  splitStatements,
  statementAtCursor,
} from "../lib/sqlWorkspace";

describe("statement boundaries", () => {
  it("splits on semicolons outside literals, identifiers, dollar bodies and comments", () => {
    const text = `SELECT 'a;b' AS "x;y"; -- c;d
      CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql; /* e; /* nested; */ f; */ SELECT 2`;
    expect(splitStatements(text).map((s) => s.text)).toEqual([
      `SELECT 'a;b' AS "x;y"`,
      "-- c;d\n      CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql",
      "/* e; /* nested; */ f; */ SELECT 2",
    ]);
  });

  it("drops blank and comment-only pieces", () => {
    expect(splitStatements(";; -- only a comment\n;")).toEqual([]);
  });

  it("runs the whole text when it is one statement, else the statement at the cursor", () => {
    expect(statementAtCursor("SELECT 1;", 0)).toBe("SELECT 1");
    const text = "SELECT 1;\nSELECT 2;\nSELECT 3";
    expect(statementAtCursor(text, text.indexOf("2"))).toBe("SELECT 2");
    expect(statementAtCursor(text, text.indexOf(";\nSELECT 3") + 1)).toBe("SELECT 2");
    expect(statementAtCursor(text, text.length)).toBe("SELECT 3");
  });
});

describe("confirmation guard (UX only)", () => {
  it("flags DROP, TRUNCATE and unqualified DELETE / UPDATE", () => {
    const kinds = dangerousStatements(
      "drop table t; truncate t; delete from t; update t set a = 1; delete from t where id = 1; update t set a=1 where b=2",
    ).map((d) => d.kind);
    expect(kinds).toEqual(["drop", "truncate", "delete-without-where", "update-without-where"]);
  });

  it("is not fooled by keywords inside literals or comments", () => {
    expect(dangerousStatements("SELECT 'drop table t' -- truncate\n")).toEqual([]);
    expect(dangerousStatements("DELETE FROM t /* WHERE id = 1 */").map((d) => d.kind)).toEqual(["delete-without-where"]);
    expect(dangerousStatements("DELETE FROM t WHERE 'x' = 'where'")).toEqual([]);
  });

  it("looks past a leading WITH", () => {
    expect(dangerousStatements("WITH x AS (SELECT 1) DELETE FROM t").map((d) => d.kind)).toEqual([
      "delete-without-where",
    ]);
    expect(dangerousStatements("WITH x AS (SELECT 1) SELECT * FROM x")).toEqual([]);
    // A WHERE inside the CTE or a subquery does not qualify the outer statement.
    expect(dangerousStatements("WITH x AS (SELECT 1 FROM a WHERE b) DELETE FROM t").map((d) => d.kind)).toEqual([
      "delete-without-where",
    ]);
    expect(dangerousStatements("UPDATE t SET a = (SELECT 1 FROM u WHERE u.id = 2)").map((d) => d.kind)).toEqual([
      "update-without-where",
    ]);
  });
});

describe("formatter", () => {
  it("upper-cases keywords and breaks major clauses without touching literals", () => {
    expect(formatSql("select a, 'from where' from t left join u on t.id = u.id where a = 1 order by a")).toBe(
      "SELECT a, 'from where'\nFROM t\nLEFT JOIN u ON t.id = u.id\nWHERE a = 1\nORDER BY a",
    );
  });

  it("keeps subqueries on one line and identifiers as written", () => {
    expect(formatSql('select "From" from (select 1 from x) s')).toBe('SELECT "From"\nFROM (SELECT 1 FROM x) s');
  });

  it("builds EXPLAIN and the Open statement with quoted identifiers", () => {
    expect(explainOf("select 1;  ")).toBe("EXPLAIN select 1");
    expect(quoteIdent('we"ird')).toBe('"we""ird"');
    expect(selectAllFrom("public", "Users")).toBe('SELECT * FROM "public"."Users" LIMIT 500;');
  });
});

describe("plugin errors", () => {
  it("reads the stable code the plugin prefixes", () => {
    expect(parsePluginError("plugin dbms-management returned status 4: session_busy: one at a time")).toEqual({
      code: "session_busy",
      message: "one at a time",
    });
    expect(parsePluginError(new Error("use_script: two statements"))).toEqual({
      code: "use_script",
      message: "two statements",
    });
    expect(parsePluginError("HTTP 403: permission denied").code).toBeNull();
  });

  it("explains the codes an operator can act on", () => {
    expect(describeSqlError("plugin p returned status 4: session_on_other_node: node abc")).toMatch(/another vault node/);
    expect(isSessionGone("plugin p returned status 4: session_on_other_node: x")).toBe(true);
    expect(isSessionGone("plugin p returned status 2: not_found: no such session")).toBe(true);
    expect(isSessionGone("the SQL session has ended")).toBe(true);
    expect(isSessionGone("plugin p returned status 2: not_found: no such run")).toBe(false);
  });

  it("states each refused check against its target", () => {
    expect(
      refusals([
        {
          index: 0,
          kinds: ["Update"],
          unclassified: false,
          verdict: "refused",
          required: [
            { capability: "sql_select", target: { catalog: "app", schema: "public", object: "t" }, allowed: true },
            { capability: "sql_update", target: { catalog: "app", schema: "public", object: "t" }, allowed: false },
            { capability: "sql_admin", target: "server", allowed: false, denied_by_deny: true },
          ],
        },
      ]),
    ).toEqual(["needs `sql_update` on `app.public.t`", "needs `sql_admin` on `the server` (an explicit deny)"]);
  });
});

const COLUMNS: SqlColumn[] = [
  { name: "id", type: "int4", kind: "number" },
  { name: "email", type: "text", kind: "string" },
  { name: "doc", type: "jsonb", kind: "json" },
];

const DESCRIBE: SqlDescribe = {
  catalog: "app",
  schema: "public",
  name: "users",
  kind: "table",
  definition: null,
  columns: [],
  constraints: [],
  indexes: [],
  triggers: [],
  routines: [],
  edit: { editable: true, key: ["id"], reason: null },
};

describe("cells and edits", () => {
  it("shows NULL apart from the empty string and summarises binary", () => {
    expect(cellText(null, "string")).toBe("NULL");
    expect(cellText("", "string")).toBe("");
    expect(cellText("AAAA", "binary")).toBe("(3 bytes, binary)");
    expect(cellText({ a: 1 }, "json")).toBe('{"a":1}');
    expect(editableKind("json")).toBe(false);
    expect(editableKind("binary")).toBe(false);
    expect(editableKind("datetime")).toBe(true);
  });

  it("explains why a result is read-only", () => {
    expect(gridEditBlocker(null, COLUMNS)).toMatch(/open a table/);
    expect(gridEditBlocker({ ...DESCRIBE, edit: { editable: false, key: null, reason: "no key" } }, COLUMNS)).toBe("no key");
    expect(gridEditBlocker(DESCRIBE, COLUMNS.slice(1))).toMatch(/key column\(s\) id/);
    expect(gridEditBlocker(DESCRIBE, COLUMNS)).toBeNull();
  });

  it("builds structured edits with the key and the originals of edited columns", () => {
    const target = { schema: "public", name: "users", key: ["id"] };
    const row = [7, "a@x", { a: 1 }];
    expect(buildUpdate(target, COLUMNS, row, { email: "b@x" })).toEqual({
      object: { schema: "public", name: "users" },
      op: "update",
      key: { id: 7 },
      values: { email: "b@x" },
      original: { email: "a@x" },
    });
    expect(buildDelete(target, COLUMNS, row)).toEqual({
      object: { schema: "public", name: "users" },
      op: "delete",
      key: { id: 7 },
    });
    expect(buildInsert(target, { email: "c@x" })).toEqual({
      object: { schema: "public", name: "users" },
      op: "insert",
      values: { email: "c@x" },
    });
    expect(() => buildUpdate(target, COLUMNS, row, {})).toThrow(/nothing changed/);
    expect(() => buildDelete(target, COLUMNS, [null, "a", null])).toThrow(/NULL/);
    expect(() => buildInsert(target, {})).toThrow();
  });

  it("never carries SQL text in an edit", () => {
    const edit = buildUpdate({ schema: "s", name: "t", key: ["id"] }, COLUMNS, [1, "x", null], {
      email: "'; DROP TABLE t; --",
    });
    expect(Object.keys(edit).sort()).toEqual(["key", "object", "op", "original", "values"]);
    expect(edit.values).toEqual({ email: "'; DROP TABLE t; --" });
  });
});
