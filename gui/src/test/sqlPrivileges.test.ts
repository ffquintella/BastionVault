import { describe, it, expect } from "vitest";
import {
  SQL_CAPABILITIES,
  SQL_PRESETS,
  activeSqlPreset,
  applySqlPreset,
  describeSqlWriteError,
  encodeSqlObjectTriple,
  explainSqlCheck,
  isResourcePolicyPath,
  namesSql,
  parseSqlCheckPath,
  sqlGateRefusal,
} from "../lib/sqlPrivileges";

/** The 409 the server sends while the write gate is closed (`gate_closed_error`). */
const GATE_409 =
  "Error response status 409: policy `dba` names sql_* capabilities, which cannot be written until every cluster " +
  "node parses them (policy schema 2, plugin host ABI 1.4): node 3: no version record: it runs a build older than " +
  "the SQL write gate. `v2/sys/policy-schema` reports each node (features/sql-browser.md §13)";

describe("the SQL capability vocabulary", () => {
  it("is the eleven names of the spec, in order", () => {
    expect([...SQL_CAPABILITIES]).toEqual([
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
    ]);
  });

  it("names SQL only for a sql_* capability", () => {
    expect(namesSql(["read", "connect"])).toBe(false);
    expect(namesSql(["read", "sql_select"])).toBe(true);
    expect(namesSql(undefined)).toBe(false);
  });
});

describe("share presets (spec §3.1, §3.3)", () => {
  const caps = (id: string) => SQL_PRESETS.find((p) => p.id === id)!.caps;

  it("bundle the capabilities of the spec, each extending the one before", () => {
    expect(caps("read-only")).toEqual(["sql_select"]);
    expect(caps("read-write")).toEqual(["sql_select", "sql_insert", "sql_update", "sql_delete"]);
    expect(caps("schema-change")).toEqual([...caps("read-write"), "sql_alter", "sql_create", "sql_drop"]);
    expect(caps("full")).toEqual([...caps("schema-change"), "sql_execute", "sql_admin"]);
  });

  it("never carry sql_export or sql_script, which stay separate toggles", () => {
    for (const p of SQL_PRESETS) {
      expect(p.caps).not.toContain("sql_export");
      expect(p.caps).not.toContain("sql_script");
    }
  });

  it("replace the SQL part of a selection and keep the rest, the two toggles included", () => {
    const rw = SQL_PRESETS[1];
    expect(applySqlPreset(["connect", "sql_select", "sql_drop", "sql_export"], rw)).toEqual([
      "connect",
      "sql_select",
      "sql_insert",
      "sql_update",
      "sql_delete",
      "sql_export",
    ]);
    // `read` is never added by a preset.
    expect(applySqlPreset([], SQL_PRESETS[0])).toEqual(["sql_select"]);
  });

  it("report the preset a selection matches, ignoring the toggles", () => {
    expect(activeSqlPreset(["sql_select"])).toBe("read-only");
    expect(activeSqlPreset(["sql_select", "sql_export", "sql_script"])).toBe("read-only");
    expect(activeSqlPreset(["read", "sql_select", "sql_insert", "sql_update", "sql_delete"])).toBe("read-write");
    expect(activeSqlPreset(["sql_select", "sql_update"])).toBeNull();
    expect(activeSqlPreset([])).toBeNull();
  });
});

describe("which paths offer the chips", () => {
  it("offers them on resource paths, in any namespace", () => {
    expect(isResourcePolicyPath("resources/resources/netrisk-db/sql/*")).toBe(true);
    expect(isResourcePolicyPath("resources/resources/+/sql/*")).toBe(true);
    expect(isResourcePolicyPath("/resources/resources/db")).toBe(true);
    expect(isResourcePolicyPath("resources/*")).toBe(true);
    expect(isResourcePolicyPath("ns1/ns2/resources/resources/db/sql/*")).toBe(true);
  });

  it("does not on other paths", () => {
    expect(isResourcePolicyPath("secret/data/team/*")).toBe(false);
    expect(isResourcePolicyPath("")).toBe(false);
    expect(isResourcePolicyPath("sys/policies/acl/*")).toBe(false);
    expect(isResourcePolicyPath("resourcesx/resources/a")).toBe(false);
  });
});

describe("reading a check path (spec §3.2)", () => {
  it("reads the server path", () => {
    expect(parseSqlCheckPath("resources/resources/db/sql/server")).toEqual({ kind: "server", resource: "db" });
  });

  it("reads an object path into catalog, schema and object", () => {
    expect(parseSqlCheckPath("resources/resources/db/sql/objects/def/netrisk/users")).toEqual({
      kind: "object",
      resource: "db",
      catalog: "def",
      schema: "netrisk",
      object: "users",
    });
  });

  it("reads the unaddressable-object bucket, with or without the trailing slash", () => {
    expect(parseSqlCheckPath("resources/resources/db/sql/objects/")?.kind).toBe("objects-root");
    expect(parseSqlCheckPath("resources/resources/db/sql/objects")?.kind).toBe("objects-root");
  });

  it("flags a malformed object path and ignores a path outside sql/", () => {
    expect(parseSqlCheckPath("resources/resources/db/sql/objects/def/netrisk")?.kind).toBe("malformed");
    expect(parseSqlCheckPath("resources/resources/db/sql/other")?.kind).toBe("malformed");
    expect(parseSqlCheckPath("resources/resources/db")).toBeNull();
    expect(parseSqlCheckPath("secret/data/x")).toBeNull();
  });
});

describe("explaining a validator case", () => {
  it("is silent for a capability that is not a SQL one", () => {
    expect(explainSqlCheck("resources/resources/db/sql/server", "read")).toBeNull();
  });

  it("explains an object check against its synthetic path", () => {
    const e = explainSqlCheck("resources/resources/db/sql/objects/def/netrisk/users", "sql_update")!;
    expect(e.warning).toBeUndefined();
    const text = e.lines.join(" ");
    expect(text).toContain("def.netrisk.users");
    expect(text).toContain("resource db");
    expect(text).toContain("…/sql/server");
  });

  it("explains a server-level check", () => {
    const e = explainSqlCheck("resources/resources/db/sql/server", "sql_select")!;
    expect(e.lines.join(" ")).toMatch(/Server-level check of sql_select/);
    expect(e.lines.join(" ")).toMatch(/opening a session/);
  });

  it("explains the bucket unaddressable names fall into", () => {
    const e = explainSqlCheck("resources/resources/db/sql/objects/", "sql_select")!;
    expect(e.lines.join(" ")).toMatch(/cannot be addressed/);
  });

  it("warns that a path outside the SQL namespace never carries a check", () => {
    const e = explainSqlCheck("secret/data/x", "sql_select")!;
    expect(e.warning).toMatch(/resources\/resources\/<resource>\/sql\/server/);
  });
});

describe("the rolling-upgrade write gate message", () => {
  it("recognises the 409 and names the blocking node", () => {
    const r = sqlGateRefusal(new Error(GATE_409))!;
    expect(r.reason).toBe("node 3: no version record: it runs a build older than the SQL write gate");
    expect(r.message).toMatch(/SQL privileges cannot be saved yet/);
    expect(r.message).toContain("Blocking: node 3");
  });

  it("recognises the Tauri error shape", () => {
    expect(sqlGateRefusal({ message: GATE_409 })).not.toBeNull();
  });

  it("recognises an exchange import refusal", () => {
    const m =
      "policies naming sql_* capabilities (default) cannot be written while the SQL write gate is closed (node 2: stale); retry";
    const r = sqlGateRefusal(new Error(m))!;
    expect(r.reason).toBe("node 2: stale");
  });

  it("leaves any other error alone", () => {
    expect(sqlGateRefusal(new Error("permission denied"))).toBeNull();
    expect(describeSqlWriteError(new Error("permission denied"))).toBe("permission denied");
    expect(describeSqlWriteError(new Error(GATE_409))).toMatch(/cannot be saved yet/);
  });
});

describe("the object list of the privileges query", () => {
  it("percent-encodes the three separators", () => {
    expect(encodeSqlObjectTriple("db", "sch/ema", "a,b%c")).toBe("db/sch%2Fema/a%2Cb%25c");
  });
});
