//! The `sql` connection profile on a database resource, GUI side
//! (features/sql-browser.md §5, §10; T124 Phase 1, subsystem 6).
//!
//! Mirrors the strict parser in `crates/bv-engine-resource/src/sql_profile.rs`
//! field for field: the GUI emits only what the backend accepts, and reads a
//! stored profile with the same rules, so one the backend would refuse is
//! shown as such instead of being defaulted.

import { newProfileId } from "./connectionProfiles";
import { SQL_CAPABILITIES, isSqlCapability, type SqlCapability } from "./sqlPrivileges";

// `sql` profiles stay outside `ConnectionProfile` / `readProfiles`: the
// launcher, the palette and the session code know four protocols and must
// never see this one. They reach the store as "unknown" entries
// (`readUnknownProfiles`) and `profilesForWrite` re-appends them (T102).

export const SQL_PROTOCOL = "sql";

// Backend limits (`sql_profile.rs`, `bv_kernel_api::policy::SQL_MAX_NAME_LEN`).
const MAX_ID_LEN = 128;
const MAX_LABEL_LEN = 256;
const MAX_NAME_LEN = 512;
const MAX_CA_PEM_LEN = 64 * 1024;
const MAX_HOST_LEN = 253;

// ── engines ─────────────────────────────────────────────────────────────

export type SqlEngineId = "postgresql" | "mysql" | "mariadb" | "mssql" | "oracle";

export interface SqlEngineInfo {
  id: SqlEngineId;
  label: string;
  port: number;
  /** What `sql.catalog` names on this engine (spec §5.1). */
  catalogLabel: string;
}

export const SQL_ENGINES: readonly SqlEngineInfo[] = [
  { id: "postgresql", label: "PostgreSQL", port: 5432, catalogLabel: "Database" },
  { id: "mysql", label: "MySQL", port: 3306, catalogLabel: "Database" },
  { id: "mariadb", label: "MariaDB", port: 3306, catalogLabel: "Database" },
  { id: "mssql", label: "Microsoft SQL Server", port: 1433, catalogLabel: "Database" },
  { id: "oracle", label: "Oracle Database", port: 1521, catalogLabel: "Service name" },
];

/** The five spellings the `database` type's `engine` select stores; anything else is `null`. */
export function sqlEngineOf(resource: Record<string, unknown>): SqlEngineInfo | null {
  const engine = resource["engine"];
  return SQL_ENGINES.find((e) => e.id === engine) ?? null;
}

// ── shapes ──────────────────────────────────────────────────────────────

export type SqlTlsMode = "verify-full" | "verify-ca" | "require" | "disable";
export const SQL_TLS_MODES: readonly SqlTlsMode[] = ["verify-full", "verify-ca", "require", "disable"];

export type SqlCredential =
  | { kind: "secret"; secretId: string }
  /** Reserved for Phase 9 (T130): parsed by the server, never released. */
  | { kind: "dynamic"; mount: string; role: string };

/** The editor's state for one profile; every field a string the operator can type. */
export interface SqlProfileForm {
  id: string;
  name: string;
  /** Which key the stored profile used for its name. `label` wins on the server if both exist. */
  nameKey: "name" | "label";
  isDefault: boolean;
  targetHost: string;
  targetPort: string;
  catalog: string;
  instance: string;
  tlsMode: SqlTlsMode;
  tlsServerName: string;
  tlsCaPem: string;
  ceiling: SqlCapability[];
  requireMfa: boolean;
  stepUp: SqlCapability[];
  credential: SqlCredential;
}

/** A new profile: verify-full TLS, SELECT-only ceiling, no credential picked yet. */
export function blankSqlProfile(secretId = ""): SqlProfileForm {
  return {
    id: newProfileId(),
    name: "Read-only",
    nameKey: "name",
    isDefault: false,
    targetHost: "",
    targetPort: "",
    catalog: "",
    instance: "",
    tlsMode: "verify-full",
    tlsServerName: "",
    tlsCaPem: "",
    ceiling: ["sql_select"],
    requireMfa: false,
    stepUp: [],
    credential: { kind: "secret", secretId },
  };
}

// ── validation (mirrors the strict parser) ──────────────────────────────

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** UTF-8 length in bytes, which is what the backend's limits count. */
export function utf8Length(s: string): number {
  let n = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
  }
  return n;
}

function isIpv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s)) return false;
  const halves = s.split("::");
  if (halves.length > 2) return false;
  const lists = halves.map((h) => (h === "" ? [] : h.split(":")));
  const last = lists.length - 1;
  let units = 0;
  for (let li = 0; li < lists.length; li++) {
    for (let gi = 0; gi < lists[li].length; gi++) {
      const g = lists[li][gi];
      if (/^[0-9a-fA-F]{1,4}$/.test(g)) {
        units += 1;
        continue;
      }
      // A dotted IPv4 tail, allowed only as the very last group of the address.
      const isTail = li === last && gi === lists[li].length - 1;
      const v4 = g.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      if (!isTail || !v4 || v4.slice(1).some((o) => Number(o) > 255 || (o.length > 1 && o.startsWith("0")))) {
        return false;
      }
      units += 2;
    }
  }
  return halves.length === 2 ? units <= 7 : units === 8;
}

/** `dial_host` in `sql_profile.rs`: ASCII, no path or wildcard, or a bare IPv6 address. */
export function validateDialHost(raw: string, what: string): string | null {
  const bad = `${what} must be a host name or an IP address (ASCII; use punycode for an internationalized name)`;
  if (!raw || utf8Length(raw) > MAX_HOST_LEN || /[^\u0000-\u007f]/.test(raw)) return bad;
  if (raw.includes(":")) return isIpv6(raw) ? null : bad;
  if (!/^[A-Za-z0-9._-]+$/.test(raw) || raw.startsWith(".") || raw.endsWith(".") || raw.includes("..")) return bad;
  return null;
}

function validateText(value: string, max: number, what: string): string | null {
  if (CONTROL.test(value)) return `${what} must not contain control characters`;
  if (utf8Length(value) > max) return `${what} must be at most ${max} bytes`;
  return null;
}

/** A secret id / role: one path segment, no surrounding whitespace. */
function validateSegment(value: string, what: string): string | null {
  if (!value || value.includes("/") || value.trim() !== value || value === "." || value === "..") {
    return `${what} is required: a name without "/" or surrounding whitespace`;
  }
  return validateText(value, MAX_ID_LEN, what);
}

export function validateCaPem(pem: string): string | null {
  if (
    utf8Length(pem) > MAX_CA_PEM_LEN ||
    !pem.includes("-----BEGIN CERTIFICATE-----") ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(pem)
  ) {
    return `The CA must be PEM certificate text of at most ${MAX_CA_PEM_LEN} bytes`;
  }
  return null;
}

/** Every problem the backend would refuse this form for; empty when it saves. */
export function validateSqlProfile(f: SqlProfileForm, engine: SqlEngineId): string[] {
  const out: string[] = [];
  const add = (m: string | null) => m && out.push(m);

  if (!f.id.trim()) out.push("The profile needs an id");
  else add(validateText(f.id, MAX_ID_LEN, "The profile id"));
  if (!f.name.trim()) out.push("The profile needs a name");
  else add(validateText(f.name, MAX_LABEL_LEN, "The profile name"));

  const host = f.targetHost.trim();
  if (host) add(validateDialHost(host, "Host"));
  const port = f.targetPort.trim();
  if (port && !(/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) {
    out.push("Port must be an integer from 1 to 65535");
  }

  add(f.catalog ? validateText(f.catalog, MAX_NAME_LEN, "The catalog") : null);
  if (f.instance) {
    if (engine !== "mssql") out.push("An instance names a SQL Server named instance; this resource's engine is not SQL Server");
    else add(validateText(f.instance, MAX_ID_LEN, "The instance"));
  }

  const server = f.tlsServerName.trim();
  if (server) add(validateDialHost(server, "TLS server name"));
  if (f.tlsCaPem.trim()) {
    add(validateCaPem(f.tlsCaPem));
    if (f.tlsMode === "disable") out.push("A CA has no effect with TLS mode disable");
  }

  if (f.ceiling.length === 0) out.push("The ceiling must name at least one capability: what this login can do at the database");
  if (new Set(f.ceiling).size !== f.ceiling.length) out.push("The ceiling names a capability twice");
  if (new Set(f.stepUp).size !== f.stepUp.length) out.push("Step-up names a capability twice");

  if (f.credential.kind === "secret") {
    add(validateSegment(f.credential.secretId, "The credential secret"));
  } else {
    if (!f.credential.mount || /\s/.test(f.credential.mount)) out.push("The dynamic credential mount is required");
    add(validateSegment(f.credential.role, "The dynamic credential role"));
  }
  return out;
}

// ── write shape ─────────────────────────────────────────────────────────

/**
 * The profile as the backend accepts it: only the keys of §5.1, optional
 * fields omitted when empty, `require_mfa` under `sql` (a top-level one is
 * refused). Assumes {@link validateSqlProfile} passed.
 */
export function serializeSqlProfile(f: SqlProfileForm): Record<string, unknown> {
  const target: Record<string, unknown> = {};
  if (f.targetHost.trim()) target.host = f.targetHost.trim();
  if (f.targetPort.trim()) target.port = Number(f.targetPort.trim());

  const tls: Record<string, unknown> = { mode: f.tlsMode };
  if (f.tlsServerName.trim()) tls.server_name = f.tlsServerName.trim();
  if (f.tlsCaPem.trim()) tls.ca_pem = f.tlsCaPem;

  const sql: Record<string, unknown> = {};
  if (f.catalog) sql.catalog = f.catalog;
  if (f.instance) sql.instance = f.instance;
  sql.tls = tls;
  // Canonical vocabulary order, whatever order the chips were clicked in.
  sql.ceiling = SQL_CAPABILITIES.filter((c) => f.ceiling.includes(c));
  sql.require_mfa = f.requireMfa;
  if (f.stepUp.length > 0) sql.step_up = SQL_CAPABILITIES.filter((c) => f.stepUp.includes(c));

  const credential_source =
    f.credential.kind === "secret"
      ? { kind: "secret", secret_id: f.credential.secretId }
      : { kind: "dynamic", mount: f.credential.mount, role: f.credential.role };

  const out: Record<string, unknown> = { id: f.id, [f.nameKey]: f.name.trim(), protocol: SQL_PROTOCOL };
  if (f.isDefault) out.is_default = true;
  if (Object.keys(target).length > 0) out.target = target;
  out.sql = sql;
  out.credential_source = credential_source;
  return out;
}

// ── read shape (strict, like the backend) ───────────────────────────────

const PROFILE_KEYS = ["id", "name", "label", "is_default", "protocol", "target", "sql", "credential_source"];
const SQL_BLOCK_KEYS = ["catalog", "instance", "tls", "ceiling", "require_mfa", "step_up"];

export interface SqlProfileRead {
  /** The form to edit; best effort when `problems` is not empty. */
  form: SqlProfileForm;
  /** Why the backend would refuse the stored profile; empty when it parses. */
  problems: string[];
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Is this stored entry a `sql` profile (whatever its shape)? */
export function isSqlProfileEntry(p: unknown): boolean {
  return isObject(p) && p["protocol"] === SQL_PROTOCOL;
}

/**
 * Read a stored `sql` profile with the backend's strictness. Anything the
 * server would refuse (an unknown key, a wrong type, a value outside its
 * vocabulary) is reported in `problems` instead of being defaulted, and the
 * form still carries whatever could be read, so the operator can repair the
 * profile by saving it. Saving drops keys the server would not accept.
 */
export function readSqlProfile(raw: unknown, engine: SqlEngineId): SqlProfileRead {
  const problems: string[] = [];
  const form = blankSqlProfile();
  form.id = "";
  form.name = "";
  form.ceiling = [];
  if (!isObject(raw)) return { form, problems: ["the profile is not an object"] };

  const unknownKeys = (o: Record<string, unknown>, allowed: string[], what: string) => {
    const k = Object.keys(o).find((key) => !allowed.includes(key));
    if (k !== undefined) problems.push(`${what} has an unknown key \`${k.slice(0, 64)}\``);
  };
  /** Absent, null and "" are unset; a non-string is a problem. */
  const text = (o: Record<string, unknown>, key: string, what: string): string => {
    const v = o[key];
    if (v === undefined || v === null || v === "") return "";
    if (typeof v === "string") return v;
    problems.push(`${what} \`${key}\` must be a string`);
    return "";
  };

  unknownKeys(raw, PROFILE_KEYS, "the profile");
  form.id = text(raw, "id", "the profile");
  const label = text(raw, "label", "the profile");
  const name = text(raw, "name", "the profile");
  form.nameKey = label ? "label" : "name";
  form.name = label || name;
  if (raw["is_default"] !== undefined && raw["is_default"] !== null && typeof raw["is_default"] !== "boolean") {
    problems.push("the profile `is_default` must be a boolean");
  }
  form.isDefault = raw["is_default"] === true;

  const target = raw["target"];
  if (target !== undefined && target !== null) {
    if (!isObject(target)) problems.push("`target` must be an object");
    else {
      unknownKeys(target, ["host", "port"], "`target`");
      form.targetHost = text(target, "host", "`target`");
      const p = target["port"];
      if (p !== undefined && p !== null) {
        if (typeof p === "number" && Number.isInteger(p)) form.targetPort = String(p);
        else problems.push("`target` `port` must be an integer in 1..=65535");
      }
    }
  }

  const sql = raw["sql"];
  if (!isObject(sql)) problems.push("an sql profile needs its `sql` block");
  else {
    unknownKeys(sql, SQL_BLOCK_KEYS, "`sql`");
    form.catalog = text(sql, "catalog", "`sql`");
    form.instance = text(sql, "instance", "`sql`");
    const tls = sql["tls"];
    if (tls !== undefined && tls !== null) {
      if (!isObject(tls)) problems.push("`sql.tls` must be an object");
      else {
        unknownKeys(tls, ["mode", "server_name", "ca_pem"], "`sql.tls`");
        const mode = tls["mode"];
        if (mode === undefined || mode === null) form.tlsMode = "verify-full";
        else if (typeof mode === "string" && (SQL_TLS_MODES as readonly string[]).includes(mode)) {
          form.tlsMode = mode as SqlTlsMode;
        } else problems.push("`sql.tls.mode` must be verify-full, verify-ca, require or disable");
        form.tlsServerName = text(tls, "server_name", "`sql.tls`");
        form.tlsCaPem = text(tls, "ca_pem", "`sql.tls`");
      }
    }
    const capList = (key: string, required: boolean): SqlCapability[] => {
      const v = sql[key];
      if (v === undefined || v === null) {
        if (required) problems.push("`sql.ceiling` is required: the sql_* capabilities this profile's login can use");
        return [];
      }
      if (!Array.isArray(v)) {
        problems.push(`\`sql.${key}\` must be a list`);
        return [];
      }
      const names = v.filter((x): x is string => typeof x === "string" && isSqlCapability(x));
      if (names.length !== v.length) problems.push(`\`sql.${key}\` may name only the eleven sql_* capabilities`);
      const unique = names.filter((c, i) => names.indexOf(c) === i);
      if (unique.length !== names.length) problems.push(`\`sql.${key}\` names a capability twice`);
      return unique as SqlCapability[];
    };
    form.ceiling = capList("ceiling", true);
    form.stepUp = capList("step_up", false);
    const mfa = sql["require_mfa"];
    if (mfa !== undefined && mfa !== null && typeof mfa !== "boolean") {
      problems.push("`sql.require_mfa` must be a boolean");
    }
    // Anything but an absent or false value gates the profile on the server,
    // so a non-boolean reads as "on" here as well.
    form.requireMfa = !(mfa === undefined || mfa === null || mfa === false);
  }

  const cs = raw["credential_source"];
  if (!isObject(cs)) problems.push("`credential_source` is required and must be an object");
  else if (cs["kind"] === "secret") {
    unknownKeys(cs, ["kind", "secret_id"], "`credential_source`");
    form.credential = { kind: "secret", secretId: text(cs, "secret_id", "`credential_source`") };
  } else if (cs["kind"] === "dynamic") {
    unknownKeys(cs, ["kind", "mount", "role"], "`credential_source`");
    form.credential = {
      kind: "dynamic",
      mount: text(cs, "mount", "`credential_source`"),
      role: text(cs, "role", "`credential_source`"),
    };
  } else {
    problems.push("an sql profile's `credential_source.kind` must be `secret` (or `dynamic`, reserved)");
  }

  // The semantic rules the form's own validation applies (host syntax,
  // lengths, tls.ca_pem with disable, instance on a non-SQL-Server engine).
  if (problems.length === 0) problems.push(...validateSqlProfile(form, engine));
  return { form, problems };
}

// ── endpoint ────────────────────────────────────────────────────────────

function recordHost(meta: Record<string, unknown>, key: string): string {
  const v = meta[key];
  return typeof v === "string" ? v.trim() : "";
}

function recordPort(meta: Record<string, unknown>): number | null {
  const v = meta["port"];
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v.trim()) : 0;
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/**
 * The `host:port` a profile dials, as the server resolves it (§5.1): the
 * profile's `target.host`, else the resource's `hostname`, else its
 * `ip_address`; the profile's port, else the resource's `port`, else the
 * engine's default. IPv6 hosts are bracketed. This is the string a resource
 * secret's `sql_endpoint` must name for the login to be released (§5.4).
 */
export function resolveSqlEndpoint(
  form: Pick<SqlProfileForm, "targetHost" | "targetPort">,
  resource: Record<string, unknown>,
  engine: SqlEngineInfo,
): string | null {
  const host = (form.targetHost.trim() || recordHost(resource, "hostname") || recordHost(resource, "ip_address")).toLowerCase();
  if (!host) return null;
  const port = /^\d+$/.test(form.targetPort.trim()) ? Number(form.targetPort.trim()) : (recordPort(resource) ?? engine.port);
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

// ── the resource's own `sql` block (enforcement) ────────────────────────

export type SqlEnforcement = "database-first" | "classifier-only";

export interface SqlEnforcementRead {
  value: SqlEnforcement;
  /** Set when the stored block is one the backend refuses. */
  problem: string | null;
}

/** Read the record's `sql.enforcement`: absent is the default `database-first`. */
export function readSqlEnforcement(resource: Record<string, unknown>): SqlEnforcementRead {
  const block = resource["sql"];
  const dflt: SqlEnforcement = "database-first";
  if (block === undefined || block === null) return { value: dflt, problem: null };
  if (!isObject(block)) return { value: dflt, problem: "the resource's `sql` must be an object" };
  const extra = Object.keys(block).find((k) => k !== "enforcement");
  if (extra !== undefined) return { value: dflt, problem: `the resource's \`sql\` has an unknown key \`${extra.slice(0, 64)}\`` };
  const e = block["enforcement"];
  if (e === undefined || e === null) return { value: dflt, problem: null };
  if (e === "database-first" || e === "classifier-only") return { value: e, problem: null };
  return { value: dflt, problem: "`sql.enforcement` must be \"database-first\" or \"classifier-only\"" };
}

/**
 * The record with `sql.enforcement` set. The block carries nothing else (the
 * backend refuses other keys), so it is rewritten whole; the default is
 * dropped unless the record already had a block, to leave records that never
 * opted in as they were.
 */
export function withSqlEnforcement(resource: Record<string, unknown>, value: SqlEnforcement): Record<string, unknown> {
  const next = { ...resource };
  if (value === "database-first" && !("sql" in resource)) return next;
  next["sql"] = { enforcement: value };
  return next;
}

// ── the database type's Connect block ───────────────────────────────────

export type SqlTypeGate =
  /** Offered: nothing saved, or `sql` is on the saved list. */
  | { offered: true; explicitList: boolean }
  | { offered: false; reason: "disabled" | "missing-from-list" | "not-a-list" | "unreadable" };

/**
 * Is `sql` offered under the saved `database` type? Same decision as
 * `sql_offered_by_type` in the backend: no `connect` block, or no
 * `protocols` key, offers it; `enabled = false` turns everything off; a
 * `protocols` list offers what it names, any other value nothing; a
 * `connect` that is not an object is unreadable.
 */
export function sqlOfferedByType(typeDef: { connect?: unknown } | null | undefined): SqlTypeGate {
  const connect = typeDef?.connect;
  if (connect === undefined || connect === null) return { offered: true, explicitList: false };
  if (!isObject(connect)) return { offered: false, reason: "unreadable" };
  const enabled = connect["enabled"];
  if (enabled === false) return { offered: false, reason: "disabled" };
  if (enabled !== undefined && enabled !== null && enabled !== true) return { offered: false, reason: "unreadable" };
  const list = connect["protocols"];
  if (list === undefined || list === null) return { offered: true, explicitList: false };
  if (!Array.isArray(list)) return { offered: false, reason: "not-a-list" };
  return list.includes(SQL_PROTOCOL)
    ? { offered: true, explicitList: true }
    : { offered: false, reason: "missing-from-list" };
}

/** The type's `connect` block with `sql` appended to its explicit list (other entries untouched). */
export function connectWithSql(connect: Record<string, unknown>): Record<string, unknown> {
  const list = Array.isArray(connect["protocols"]) ? (connect["protocols"] as unknown[]) : [];
  return { ...connect, protocols: list.includes(SQL_PROTOCOL) ? list : [...list, SQL_PROTOCOL] };
}
