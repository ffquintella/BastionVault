import { describe, it, expect } from "vitest";
import {
  SQL_ENGINES,
  blankSqlProfile,
  connectWithSql,
  isSqlProfileEntry,
  readSqlEnforcement,
  readSqlProfile,
  resolveSqlEndpoint,
  serializeSqlProfile,
  sqlEngineOf,
  sqlOfferedByType,
  validateDialHost,
  validateSqlProfile,
  withSqlEnforcement,
  type SqlProfileForm,
} from "../lib/sqlProfile";
import { profilesForWrite, readProfiles, readUnknownProfiles } from "../lib/connectionProfiles";

/** The keys `crates/bv-engine-resource/src/sql_profile.rs` accepts, level by level. */
const TOP = ["id", "name", "label", "is_default", "protocol", "target", "sql", "credential_source"];
const SQL = ["catalog", "instance", "tls", "ceiling", "require_mfa", "step_up"];
const TLS = ["mode", "server_name", "ca_pem"];
const SECRET = ["kind", "secret_id"];
const DYNAMIC = ["kind", "mount", "role"];

const subset = (o: Record<string, unknown>, allowed: string[]) =>
  Object.keys(o).every((k) => allowed.includes(k));

/** Everything a serialized profile carries must be a key the backend accepts. */
function expectBackendShape(p: Record<string, unknown>) {
  expect(subset(p, TOP)).toBe(true);
  expect(p["protocol"]).toBe("sql");
  const sql = p["sql"] as Record<string, unknown>;
  expect(subset(sql, SQL)).toBe(true);
  expect(subset(sql["tls"] as Record<string, unknown>, TLS)).toBe(true);
  if (p["target"]) expect(subset(p["target"] as Record<string, unknown>, ["host", "port"])).toBe(true);
  const cs = p["credential_source"] as Record<string, unknown>;
  expect(subset(cs, cs["kind"] === "secret" ? SECRET : DYNAMIC)).toBe(true);
}

function form(over: Partial<SqlProfileForm> = {}): SqlProfileForm {
  return { ...blankSqlProfile("svc_ro"), id: "p_1", name: "Read-only", ...over };
}

const POSTGRES = "postgresql" as const;

describe("serializing a profile", () => {
  it("emits only what the backend accepts, for the default form", () => {
    const p = serializeSqlProfile(form());
    expectBackendShape(p);
    expect(p).toEqual({
      id: "p_1",
      name: "Read-only",
      protocol: "sql",
      sql: { tls: { mode: "verify-full" }, ceiling: ["sql_select"], require_mfa: false },
      credential_source: { kind: "secret", secret_id: "svc_ro" },
    });
  });

  it("emits every optional field once it is set, and `require_mfa` under `sql`, never at the top", () => {
    const p = serializeSqlProfile(
      form({
        targetHost: "db1.example.net",
        targetPort: "3306",
        catalog: "netrisk",
        instance: "SQLEXPRESS",
        tlsMode: "verify-ca",
        tlsServerName: "db1.example.net",
        tlsCaPem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ceiling: ["sql_update", "sql_select"],
        requireMfa: true,
        stepUp: ["sql_script", "sql_drop"],
      }),
    );
    expectBackendShape(p);
    expect("require_mfa" in p).toBe(false);
    expect(p["target"]).toEqual({ host: "db1.example.net", port: 3306 });
    expect(p["sql"]).toEqual({
      catalog: "netrisk",
      instance: "SQLEXPRESS",
      tls: {
        mode: "verify-ca",
        server_name: "db1.example.net",
        ca_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
      },
      // Canonical vocabulary order, whatever order they were chosen in.
      ceiling: ["sql_select", "sql_update"],
      require_mfa: true,
      step_up: ["sql_drop", "sql_script"],
    });
  });

  it("omits what is empty rather than sending an empty string", () => {
    const p = serializeSqlProfile(form({ targetHost: "  ", targetPort: " ", catalog: "", stepUp: [] }));
    expect("target" in p).toBe(false);
    const sql = p["sql"] as Record<string, unknown>;
    expect(sql).not.toHaveProperty("catalog");
    expect(sql).not.toHaveProperty("instance");
    expect(sql).not.toHaveProperty("step_up");
    expect(sql["tls"]).toEqual({ mode: "verify-full" });
  });

  it("writes the port as a number: the backend refuses a numeric string", () => {
    expect((serializeSqlProfile(form({ targetPort: "5432" }))["target"] as { port: unknown }).port).toBe(5432);
  });

  it("keeps the name under the key the stored profile used, and the default flag", () => {
    const p = serializeSqlProfile(form({ nameKey: "label", isDefault: true }));
    expect(p["label"]).toBe("Read-only");
    expect(p).not.toHaveProperty("name");
    expect(p["is_default"]).toBe(true);
    expect(serializeSqlProfile(form())).not.toHaveProperty("is_default");
  });

  it("writes a dynamic source in its reserved shape", () => {
    const p = serializeSqlProfile(form({ credential: { kind: "dynamic", mount: "db-pg/", role: "ro" } }));
    expectBackendShape(p);
    expect(p["credential_source"]).toEqual({ kind: "dynamic", mount: "db-pg/", role: "ro" });
  });

  it("round-trips through the strict reader without a problem", () => {
    const f = form({
      targetHost: "db1",
      targetPort: "5432",
      catalog: "app",
      requireMfa: true,
      ceiling: ["sql_select", "sql_insert"],
      stepUp: ["sql_drop"],
    });
    const read = readSqlProfile(serializeSqlProfile(f), POSTGRES);
    expect(read.problems).toEqual([]);
    expect(read.form).toEqual(f);
  });
});

describe("validating a form (the backend's own refusals)", () => {
  const errs = (over: Partial<SqlProfileForm>, engine: Parameters<typeof validateSqlProfile>[1] = POSTGRES) =>
    validateSqlProfile(form(over), engine);

  it("accepts the default form", () => {
    expect(errs({})).toEqual([]);
  });

  it("needs a name, an id and at least one ceiling capability", () => {
    expect(errs({ name: " " })).toContain("The profile needs a name");
    expect(errs({ id: "" })).toContain("The profile needs an id");
    expect(errs({ ceiling: [] }).join()).toMatch(/at least one capability/);
  });

  it("refuses a repeated capability", () => {
    expect(errs({ ceiling: ["sql_select", "sql_select"] }).join()).toMatch(/twice/);
    expect(errs({ stepUp: ["sql_drop", "sql_drop"] }).join()).toMatch(/twice/);
  });

  it.each(["db1/x", "db 1", "db1:", ".db", "db.", "a..b", "db*", "dbé", "[::1]", "http://db"])(
    "refuses the host %j",
    (host) => {
      expect(validateDialHost(host, "Host")).not.toBeNull();
    },
  );

  it.each(["db1", "db-1.example.net", "10.0.0.9", "db_1", "::1", "fd00::5", "2001:db8::1", "::ffff:10.0.0.1"])(
    "accepts the host %j",
    (host) => {
      expect(validateDialHost(host, "Host")).toBeNull();
    },
  );

  it.each(["1:2:3:4:5:6:7:8:9", ":::", "12345::1", "1::2::3", "::1.2.3", "1.2.3.4::"])("refuses the IPv6 form %j", (host) => {
    expect(validateDialHost(host, "Host")).not.toBeNull();
  });

  it.each(["0", "70000", "5432x", "-1", "1.5"])("refuses the port %j", (port) => {
    expect(errs({ targetPort: port }).join()).toMatch(/Port/);
  });

  it("refuses control characters and over-long values", () => {
    expect(errs({ catalog: "a\u0000b" }).join()).toMatch(/control characters/);
    expect(errs({ catalog: "x".repeat(513) }).join()).toMatch(/at most 512 bytes/);
    expect(errs({ name: "n".repeat(257) }).join()).toMatch(/at most 256 bytes/);
    // Bytes, not characters: 200 two-byte characters are 400 bytes.
    expect(errs({ name: "é".repeat(200) }).join()).toMatch(/at most 256 bytes/);
  });

  it("allows a named instance on SQL Server only", () => {
    expect(errs({ instance: "SQLEXPRESS" }, "mssql")).toEqual([]);
    for (const e of ["postgresql", "mysql", "mariadb", "oracle"] as const) {
      expect(errs({ instance: "SQLEXPRESS" }, e).join()).toMatch(/SQL Server/);
    }
  });

  it("checks the TLS server name and the CA", () => {
    expect(errs({ tlsServerName: "a b" }).join()).toMatch(/TLS server name/);
    expect(errs({ tlsCaPem: "not a pem" }).join()).toMatch(/PEM certificate text/);
    expect(errs({ tlsCaPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----" })).toEqual([]);
    expect(
      errs({ tlsMode: "disable", tlsCaPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----" }).join(),
    ).toMatch(/no effect with TLS mode disable/);
  });

  it("needs a credential secret that is one path segment", () => {
    for (const secretId of ["", "a/b", " x", "x ", ".", ".."]) {
      expect(errs({ credential: { kind: "secret", secretId } }).join()).toMatch(/credential secret/);
    }
  });

  it("needs a mount and a role for the reserved dynamic source", () => {
    expect(errs({ credential: { kind: "dynamic", mount: "", role: "ro" } }).join()).toMatch(/mount/);
    expect(errs({ credential: { kind: "dynamic", mount: "db-pg/", role: "a/b" } }).join()).toMatch(/role/);
    expect(errs({ credential: { kind: "dynamic", mount: "db-pg/", role: "ro" } })).toEqual([]);
  });
});

describe("reading a stored profile as strictly as the backend", () => {
  const ok = () => ({
    id: "p",
    name: "RO",
    protocol: "sql",
    sql: { ceiling: ["sql_select"] },
    credential_source: { kind: "secret", secret_id: "s" },
  });
  const read = (p: unknown, engine: Parameters<typeof readSqlProfile>[1] = POSTGRES) => readSqlProfile(p, engine);

  it("accepts the spec's example (label, target, tls, step-up)", () => {
    const r = read({
      id: "netrisk-ro",
      protocol: "sql",
      label: "Read-only (svc_netrisk_ro)",
      target: { host: "apldc1vds0044", port: 3306 },
      sql: {
        catalog: "netrisk",
        instance: null,
        tls: { mode: "verify-full", server_name: null, ca_pem: null },
        ceiling: ["sql_select"],
        require_mfa: false,
        step_up: ["sql_drop", "sql_admin", "sql_export", "sql_script"],
      },
      credential_source: { kind: "secret", secret_id: "svc_netrisk_ro" },
    }, "mysql");
    expect(r.problems).toEqual([]);
    expect(r.form.name).toBe("Read-only (svc_netrisk_ro)");
    expect(r.form.nameKey).toBe("label");
    expect(r.form.targetPort).toBe("3306");
  });

  it("defaults tls.mode to verify-full when absent", () => {
    expect(read(ok()).form.tlsMode).toBe("verify-full");
  });

  // The cases of `a_wrongly_typed_sql_block_fails_closed` in the backend's tests.
  it.each<[string, Record<string, unknown>]>([
    ["ceiling a string", { ceiling: "sql_select" }],
    ["empty ceiling", { ceiling: [] }],
    ["unknown capability", { ceiling: ["select"] }],
    ["repeated capability", { ceiling: ["sql_select", "sql_select"] }],
    ["upper-case capability", { ceiling: ["SQL_SELECT"] }],
    ["no ceiling", {}],
    ["require_mfa a string", { ceiling: ["sql_select"], require_mfa: "yes" }],
    ["require_mfa a number", { ceiling: ["sql_select"], require_mfa: 1 }],
    ["step_up a string", { ceiling: ["sql_select"], step_up: "sql_drop" }],
    ["step_up unknown", { ceiling: ["sql_select"], step_up: ["sql_nope"] }],
    ["tls a string", { ceiling: ["sql_select"], tls: "verify-full" }],
    ["tls mode prefer", { ceiling: ["sql_select"], tls: { mode: "prefer" } }],
    ["tls mode upper-case", { ceiling: ["sql_select"], tls: { mode: "VERIFY-FULL" } }],
    ["tls unknown key", { ceiling: ["sql_select"], tls: { mode: "verify-full", insecure: true } }],
    ["tls server name with a space", { ceiling: ["sql_select"], tls: { server_name: "a b" } }],
    ["ca that is not a pem", { ceiling: ["sql_select"], tls: { ca_pem: "not a pem" } }],
    [
      "ca with mode disable",
      { ceiling: ["sql_select"], tls: { mode: "disable", ca_pem: "-----BEGIN CERTIFICATE-----\nx" } },
    ],
    ["catalog a number", { ceiling: ["sql_select"], catalog: 5 }],
    ["catalog with a NUL", { ceiling: ["sql_select"], catalog: "a\u0000b" }],
    ["enforcement in the profile", { ceiling: ["sql_select"], enforcement: "classifier-only" }],
    ["instance off SQL Server", { ceiling: ["sql_select"], instance: "SQLEXPRESS" }],
  ])("reports a problem for %s", (_, sql) => {
    expect(read({ ...ok(), sql }).problems.length).toBeGreaterThan(0);
  });

  it.each<[string, Record<string, unknown>]>([
    ["unknown top-level key", { require_mfa: true }],
    ["target a string", { target: "db1" }],
    ["target with an unknown key", { target: { host: "db1", user: "x" } }],
    ["target host with a slash", { target: { host: "db1/x" } }],
    ["target port zero", { target: { port: 0 } }],
    ["target port a string", { target: { port: "5432" } }],
    ["target port too large", { target: { port: 70000 } }],
    ["is_default a string", { is_default: "yes" }],
    ["a provider source", { credential_source: { kind: "provider", provider: "self-accounts" } }],
    ["a secret source without an id", { credential_source: { kind: "secret" } }],
    ["a secret id with a slash", { credential_source: { kind: "secret", secret_id: "a/b" } }],
    ["an inline password", { credential_source: { kind: "secret", secret_id: "x", password: "inline" } }],
    ["a dynamic source without a mount", { credential_source: { kind: "dynamic", role: "ro" } }],
    ["no credential source", { credential_source: undefined }],
    ["no id", { id: undefined }],
  ])("reports a problem for %s", (_, over) => {
    expect(read({ ...ok(), ...over }).problems.length).toBeGreaterThan(0);
  });

  it("accepts the reserved dynamic source, which the server parses and never releases", () => {
    const r = read({ ...ok(), credential_source: { kind: "dynamic", mount: "db-pg/", role: "netrisk-ro" } });
    expect(r.problems).toEqual([]);
    expect(r.form.credential).toEqual({ kind: "dynamic", mount: "db-pg/", role: "netrisk-ro" });
  });

  it("reads a malformed require_mfa as on, as the server's gate does, and still reports it", () => {
    const r = read({ ...ok(), sql: { ceiling: ["sql_select"], require_mfa: "false" } });
    expect(r.form.requireMfa).toBe(true);
    expect(r.problems.join()).toMatch(/require_mfa/);
  });

  it("keeps whatever it could read, so the profile can be repaired by saving it", () => {
    const r = read({ ...ok(), target: { host: "db1", user: "x" }, sql: { ceiling: ["sql_select", "bogus"], extra: 1 } });
    expect(r.problems.length).toBeGreaterThan(1);
    expect(r.form.ceiling).toEqual(["sql_select"]);
    expect(r.form.targetHost).toBe("db1");
    const repaired = serializeSqlProfile(r.form);
    expectBackendShape(repaired);
    expect(readSqlProfile(repaired, POSTGRES).problems).toEqual([]);
  });

  it("is not fooled by a non-object", () => {
    expect(read(null).problems).toEqual(["the profile is not an object"]);
    expect(read([]).problems).toEqual(["the profile is not an object"]);
  });
});

describe("the endpoint a profile dials (and a secret's sql_endpoint must name)", () => {
  const eng = (id: string) => SQL_ENGINES.find((e) => e.id === id)!;
  const f = (h = "", p = "") => ({ targetHost: h, targetPort: p });

  it("takes the profile's host and port first", () => {
    expect(resolveSqlEndpoint(f("DB1.Example.net", "1600"), { hostname: "elsewhere", port: 1 }, eng("mysql"))).toBe(
      "db1.example.net:1600",
    );
  });

  it("then the record's hostname before its ip_address, and its port", () => {
    expect(resolveSqlEndpoint(f(), { hostname: "ORA1.corp", ip_address: "10.0.0.9" }, eng("oracle"))).toBe("ora1.corp:1521");
    expect(resolveSqlEndpoint(f(), { ip_address: "10.0.0.9", port: 1522 }, eng("oracle"))).toBe("10.0.0.9:1522");
    expect(resolveSqlEndpoint(f(), { hostname: "ora1", port: "1600" }, eng("oracle"))).toBe("ora1:1600");
  });

  it("falls back to the engine's default port and brackets IPv6", () => {
    for (const [id, port] of [["postgresql", 5432], ["mysql", 3306], ["mariadb", 3306], ["mssql", 1433], ["oracle", 1521]] as const) {
      expect(resolveSqlEndpoint(f(), { hostname: "db", port: "" }, eng(id))).toBe(`db:${port}`);
    }
    expect(resolveSqlEndpoint(f(), { hostname: "", ip_address: "FD00::5", port: 0 }, eng("mssql"))).toBe("[fd00::5]:1433");
  });

  it("is null while there is nothing to dial", () => {
    expect(resolveSqlEndpoint(f(), {}, eng("mysql"))).toBeNull();
    expect(resolveSqlEndpoint(f(), { hostname: "  " }, eng("mysql"))).toBeNull();
  });
});

describe("engines", () => {
  it("are the five the database type lists, with their default ports", () => {
    expect(SQL_ENGINES.map((e) => [e.id, e.port])).toEqual([
      ["postgresql", 5432],
      ["mysql", 3306],
      ["mariadb", 3306],
      ["mssql", 1433],
      ["oracle", 1521],
    ]);
  });

  it("are matched exactly: other engines, an empty value and another case are not SQL engines", () => {
    expect(sqlEngineOf({ engine: "oracle" })?.id).toBe("oracle");
    for (const engine of ["mongodb", "redis", "sqlite", "other", "", "PostgreSQL", undefined]) {
      expect(sqlEngineOf({ engine })).toBeNull();
    }
  });
});

describe("the resource's enforcement mode", () => {
  it("defaults to database-first", () => {
    expect(readSqlEnforcement({})).toEqual({ value: "database-first", problem: null });
    expect(readSqlEnforcement({ sql: { enforcement: "classifier-only" } }).value).toBe("classifier-only");
  });

  it("reports a block the backend refuses", () => {
    expect(readSqlEnforcement({ sql: "x" }).problem).toMatch(/must be an object/);
    expect(readSqlEnforcement({ sql: { enforcement: "none" } }).problem).toMatch(/enforcement/);
    expect(readSqlEnforcement({ sql: { enforcement: "classifier-only", mode: 1 } }).problem).toMatch(/unknown key/);
  });

  it("writes classifier-only, and leaves a record that never opted in without a block", () => {
    expect(withSqlEnforcement({ name: "db" }, "classifier-only")["sql"]).toEqual({ enforcement: "classifier-only" });
    expect(withSqlEnforcement({ name: "db" }, "database-first")).toEqual({ name: "db" });
    expect(withSqlEnforcement({ name: "db", sql: { enforcement: "classifier-only" } }, "database-first")["sql"]).toEqual({
      enforcement: "database-first",
    });
  });

  it("rewrites a block that carried a key the backend refuses", () => {
    expect(withSqlEnforcement({ sql: { enforcement: "classifier-only", mode: 1 } }, "classifier-only")["sql"]).toEqual({
      enforcement: "classifier-only",
    });
  });
});

describe("whether the saved database type offers sql", () => {
  const gate = (connect: unknown) => sqlOfferedByType({ connect });

  it("offers it when nothing is saved, or the saved block names no list", () => {
    expect(sqlOfferedByType(undefined)).toEqual({ offered: true, explicitList: false });
    expect(gate(undefined)).toEqual({ offered: true, explicitList: false });
    expect(gate({})).toEqual({ offered: true, explicitList: false });
    expect(gate({ enabled: true })).toEqual({ offered: true, explicitList: false });
    expect(gate({ protocols: null })).toEqual({ offered: true, explicitList: false });
  });

  it("offers what an explicit list names", () => {
    expect(gate({ protocols: ["sql"] })).toEqual({ offered: true, explicitList: true });
    expect(gate({ protocols: ["ssh", "sql"] })).toEqual({ offered: true, explicitList: true });
  });

  it("does not offer it when an explicit list lacks it, however the list is spelled", () => {
    expect(gate({ protocols: ["ssh"] })).toEqual({ offered: false, reason: "missing-from-list" });
    expect(gate({ protocols: [] })).toEqual({ offered: false, reason: "missing-from-list" });
    expect(gate({ protocols: ["SQL"] })).toEqual({ offered: false, reason: "missing-from-list" });
  });

  it("is off with connect disabled, a non-list, or an unreadable block", () => {
    expect(gate({ enabled: false, protocols: ["sql"] })).toEqual({ offered: false, reason: "disabled" });
    expect(gate({ protocols: "sql" })).toEqual({ offered: false, reason: "not-a-list" });
    expect(gate("x")).toEqual({ offered: false, reason: "unreadable" });
    expect(gate({ enabled: "yes" })).toEqual({ offered: false, reason: "unreadable" });
  });

  it("adds sql to an explicit list without touching the other entries", () => {
    expect(connectWithSql({ protocols: ["ssh"], default_ports: { ssh: 22 } })).toEqual({
      protocols: ["ssh", "sql"],
      default_ports: { ssh: 22 },
    });
    expect(connectWithSql({ protocols: ["sql"] })).toEqual({ protocols: ["sql"] });
    expect(sqlOfferedByType({ connect: connectWithSql({ protocols: ["ssh"] }) })).toEqual({
      offered: true,
      explicitList: true,
    });
  });
});

describe("saving beside profiles of other protocols (T102)", () => {
  const future = { id: "f1", name: "Later", protocol: "future", credential_source: { kind: "x" }, extra: { a: 1 } };
  const sql = serializeSqlProfile(form({ id: "p_sql" }));
  const ssh = {
    id: "p_ssh",
    name: "SSH",
    protocol: "ssh",
    credential_source: { kind: "secret", secret_id: "k" },
  };

  it("never lets the launcher's reader see a sql profile, so it can neither launch nor re-save it", () => {
    const meta = { connection_profiles: [ssh, sql, future] };
    expect(readProfiles(meta).map((p) => p.id)).toEqual(["p_ssh"]);
    expect(readUnknownProfiles(meta)).toEqual([sql, future]);
    expect(isSqlProfileEntry(sql)).toBe(true);
    expect(isSqlProfileEntry(future)).toBe(false);
    expect(isSqlProfileEntry(ssh)).toBe(false);
  });

  it("re-appends a sql profile and an unknown-protocol one untouched when the launcher saves", () => {
    const meta = { connection_profiles: [ssh, sql, future] };
    const written = profilesForWrite(readProfiles(meta), readUnknownProfiles(meta));
    expect(written).toContainEqual(sql);
    expect(written).toContainEqual(future);
    expect(written).toHaveLength(3);
  });

  it("editing the sql entries leaves the others byte for byte", () => {
    const meta = { connection_profiles: [ssh, sql, future] };
    const edited = serializeSqlProfile(form({ id: "p_sql", name: "Renamed" }));
    const nextUnknown = readUnknownProfiles(meta).map((p) =>
      isSqlProfileEntry(p) && (p as { id: string }).id === "p_sql" ? edited : p,
    );
    const written = profilesForWrite(readProfiles(meta), nextUnknown) as Record<string, unknown>[];
    expect(written.find((p) => p["id"] === "f1")).toBe(future);
    expect(written.find((p) => p["id"] === "p_sql")).toEqual(edited);
    // The launcher's own default normalisation may flag its first profile.
    expect(written.find((p) => p["id"] === "p_ssh")).toMatchObject(ssh);
  });
});
