//! SQL privilege vocabulary for the GUI (features/sql-browser.md §3, §10).
//!
//! The eleven `sql_*` capabilities, the Sharing presets (§3.3), the synthetic
//! policy paths a check is evaluated on (§3.2) and the message shown when the
//! rolling-upgrade write gate refuses a write (§13). Pure and dependency-free
//! so the policy builder, the validator, the sharing card and their tests all
//! read one definition. Nothing here authorizes anything: the server decides.

import { extractError } from "./error";

/** The eleven SQL capabilities, in the order the chips are offered. */
export const SQL_CAPABILITIES = [
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
] as const;

export type SqlCapability = (typeof SQL_CAPABILITIES)[number];

const SQL_CAPABILITY_SET = new Set<string>(SQL_CAPABILITIES);

export function isSqlCapability(c: string): c is SqlCapability {
  return SQL_CAPABILITY_SET.has(c);
}

/** One line per capability: what it grants (spec §3.1). */
export const SQL_CAPABILITY_HINTS: Record<SqlCapability, string> = {
  sql_select: "read rows and metadata: SELECT, SHOW, DESCRIBE, plan-only EXPLAIN",
  sql_insert: "add rows: INSERT",
  sql_update: "change rows and take row or table locks: UPDATE, SELECT … FOR UPDATE",
  sql_delete: "remove rows: DELETE",
  sql_alter: "change existing objects: ALTER, COMMENT ON, RENAME, VACUUM",
  sql_create: "create objects: CREATE TABLE, VIEW, INDEX, FUNCTION, SCHEMA",
  sql_drop: "destroy objects or all their rows irreversibly: DROP, TRUNCATE",
  sql_execute: "run code whose effect cannot be determined statically: CALL, EXEC, dynamic SQL",
  sql_admin: "server-level administration: GRANT, REVOKE, users and roles, ALTER SYSTEM, KILL",
  sql_export: "bulk export of a result set",
  sql_script: "multi-statement batches and script files",
};

/** `sql_*` capabilities are not implied by anything and imply nothing. */
export const SQL_NO_IMPLICATION_NOTE =
  "No SQL capability implies another, and read, update, sudo and connect grant none of them.";

/** Shown with the SQL chips in the Sharing tab (spec §3.3). */
export const SQL_SHARE_READ_HINT =
  "read on the resource reveals its stored secrets and is not needed for the SQL browser: grant SQL privileges only.";

/** Parameter constraints are refused beside a SQL capability (spec §9.1). */
export const SQL_PARAMETERS_NOTE =
  "SQL capabilities cannot be combined with allowed_parameters, denied_parameters or required_parameters: a SQL check " +
  "never reads request parameters, so the server refuses the policy.";

// ── presets (spec §3.1, §3.3) ───────────────────────────────────────────

export interface SqlPreset {
  id: "read-only" | "read-write" | "schema-change" | "full";
  label: string;
  caps: readonly SqlCapability[];
}

const RW: readonly SqlCapability[] = ["sql_select", "sql_insert", "sql_update", "sql_delete"];
const SCHEMA: readonly SqlCapability[] = [...RW, "sql_alter", "sql_create", "sql_drop"];

/**
 * Bundles of capabilities; nothing new is stored for them. Each one extends
 * the one before it. `sql_export` and `sql_script` belong to none of them:
 * they stay separate toggles, because they leave the database's own control
 * (a file on the operator's disk, a batch of statements).
 */
export const SQL_PRESETS: readonly SqlPreset[] = [
  { id: "read-only", label: "Read only", caps: ["sql_select"] },
  { id: "read-write", label: "Read/write", caps: RW },
  { id: "schema-change", label: "Schema change", caps: SCHEMA },
  { id: "full", label: "Full", caps: [...SCHEMA, "sql_execute", "sql_admin"] },
];

/** The two capabilities no preset carries. */
export const SQL_SEPARATE_TOGGLES: readonly SqlCapability[] = ["sql_export", "sql_script"];

const PRESET_BODY = new Set<string>(SQL_CAPABILITIES.filter((c) => !SQL_SEPARATE_TOGGLES.includes(c)));

/**
 * Apply a preset to a capability selection: the preset's capabilities
 * replace the selection's SQL privileges. The two separate toggles and every
 * non-SQL capability are kept as they were.
 */
export function applySqlPreset(current: readonly string[], preset: SqlPreset): string[] {
  const kept = current.filter((c) => !isSqlCapability(c));
  const keepToggles = SQL_SEPARATE_TOGGLES.filter((c) => current.includes(c));
  const body = [...preset.caps];
  const toggles = keepToggles.filter((c) => !body.includes(c));
  // Non-SQL capabilities first, then SQL ones in the canonical order.
  const sql = SQL_CAPABILITIES.filter((c) => body.includes(c) || toggles.includes(c));
  return [...kept, ...sql];
}

/** The preset a selection matches exactly (ignoring the two toggles), or null. */
export function activeSqlPreset(current: readonly string[]): SqlPreset["id"] | null {
  const body = SQL_CAPABILITIES.filter((c) => PRESET_BODY.has(c) && current.includes(c));
  return SQL_PRESETS.find((p) => p.caps.length === body.length && p.caps.every((c) => body.includes(c)))?.id ?? null;
}

/** Whether a selection names any SQL capability. */
export function namesSql(caps: readonly string[] | undefined): boolean {
  return (caps ?? []).some(isSqlCapability);
}

// ── policy paths (spec §3.2) ────────────────────────────────────────────

const strip = (path: string) => path.replace(/^\/+/, "");

/**
 * Is this the path of a resource (`resources/resources/…`, or the broad
 * `resources/*`), optionally behind namespace segments? The SQL chips are
 * offered on such rules only.
 */
export function isResourcePolicyPath(path: string): boolean {
  return /^(?:[^/]+\/)*?resources\/(?:resources(?:\/|$)|\*)/.test(strip(path));
}

export type SqlCheckPath =
  | { kind: "server"; resource: string }
  | { kind: "object"; resource: string; catalog: string; schema: string; object: string }
  /** `…/sql/objects/`: where an object whose name cannot be addressed is checked. */
  | { kind: "objects-root"; resource: string }
  /** Under `…/sql/` but not a path a check is ever evaluated on. */
  | { kind: "malformed"; resource: string; why: string };

/**
 * Read a concrete path as the synthetic ACL path a SQL check is evaluated on
 * (`resources/resources/<R>/sql/server`, `…/sql/objects/<catalog>/<schema>/<object>`).
 * `null` when it is not under a resource's `sql/` at all.
 */
export function parseSqlCheckPath(path: string): SqlCheckPath | null {
  const segs = strip(path).split("/");
  const i = segs.findIndex((s, k) => s === "resources" && segs[k + 1] === "resources");
  if (i < 0 || !segs[i + 2] || segs[i + 3] !== "sql") return null;
  const resource = segs[i + 2];
  const rest = segs.slice(i + 4);
  if (rest.length === 1 && rest[0] === "server") return { kind: "server", resource };
  if (rest[0] === "objects") {
    if (rest.length === 1 || (rest.length === 2 && rest[1] === "")) return { kind: "objects-root", resource };
    if (rest.length === 4 && rest.slice(1).every((s) => s !== "")) {
      return { kind: "object", resource, catalog: rest[1], schema: rest[2], object: rest[3] };
    }
    return { kind: "malformed", resource, why: "an object check needs `objects/<catalog>/<schema>/<object>`: three names" };
  }
  return { kind: "malformed", resource, why: "only `server` and `objects/…` exist under `sql/`" };
}

export interface SqlCheckExplanation {
  /** What this check is, in order. */
  lines: string[];
  /** Why the path never matches a SQL check, when it does not. */
  warning?: string;
}

/**
 * Explain a validator case: `capability` probed on `path`. `null` when the
 * capability is not a SQL one. Mirrors §3.2 and does not evaluate anything:
 * the verdict is still the server's dry-run.
 */
export function explainSqlCheck(path: string, capability: string): SqlCheckExplanation | null {
  if (!isSqlCapability(capability)) return null;
  const parsed = parseSqlCheckPath(path.trim());
  if (!parsed) {
    return {
      lines: [],
      warning:
        `${capability} is checked only on resources/resources/<resource>/sql/server and ` +
        "resources/resources/<resource>/sql/objects/<catalog>/<schema>/<object>; no other path ever carries a SQL check.",
    };
  }
  const where = `resource ${parsed.resource}`;
  switch (parsed.kind) {
    case "server":
      return {
        lines: [
          `Server-level check of ${capability} on ${where}: statements that name no object (SELECT 1, SHOW VARIABLES), sql_admin, sql_script, and opening a session.`,
          "Opening a session needs at least one SQL capability on this path.",
        ],
      };
    case "object":
      return {
        lines: [
          `Object check of ${capability} on ${parsed.catalog}.${parsed.schema}.${parsed.object} of ${where}, evaluated on exactly this path.`,
          "A resource-wide rule (…/sql/*) or one covering every object (…/sql/objects/*) applies too; the most specific rule wins.",
          "The caller also needs a SQL capability on …/sql/server to open a session.",
        ],
      };
    case "objects-root":
      return {
        lines: [
          `An object of ${where} whose name cannot be addressed (it contains /, * or +, or a control character, or its case cannot be determined) is checked on …/sql/objects/.`,
          "No rule naming a catalog, schema or object matches there: only a grant covering every object does.",
        ],
      };
    case "malformed":
      return { lines: [], warning: `${capability}: ${parsed.why}.` };
  }
}

// ── the rolling-upgrade write gate (spec §13) ───────────────────────────

export interface SqlGateRefusal {
  /** The first blocking node and why, as the server named it; null if it did not. */
  reason: string | null;
  /** The message to show. */
  message: string;
}

/**
 * Recognise the `409` a write naming `sql_*` gets while a cluster node cannot
 * parse it yet (policy writes, share writes, exchange imports, restores), and
 * turn it into one clear sentence. `null` for any other error.
 */
export function sqlGateRefusal(e: unknown): SqlGateRefusal | null {
  const raw = extractError(e);
  if (!/sql_\*/.test(raw) || !/(cannot be written|write gate)/i.test(raw)) return null;
  const m = raw.match(/ABI 1\.\d+\):\s*([\s\S]+?)\.\s*`?v2\/sys\/policy-schema/) ?? raw.match(/closed \(([^)]+)\)/);
  const reason = m ? m[1].trim() : null;
  return {
    reason,
    message:
      "SQL privileges cannot be saved yet: every node of the cluster must run a build that understands sql_* " +
      "capabilities (policy schema 2, plugin host ABI 1.4) first, or an older node could not unseal." +
      (reason ? ` Blocking: ${reason}.` : "") +
      " The Policies page shows the status of each node.",
  };
}

/** The sentence for a failed write: the gate's, or the error's own text. */
export function describeSqlWriteError(e: unknown): string {
  return sqlGateRefusal(e)?.message ?? extractError(e);
}

/** One node in `GET v2/sys/policy-schema`. */
export interface PolicySchemaNode {
  node: string;
  member?: boolean;
  policy_schema: number | null;
  host_abi_minor: number | null;
  updated_at?: string | null;
  qualifies: boolean;
  problem?: string | null;
}

/** `GET v2/sys/policy-schema` (docs/api.md): only what the GUI reads. */
export interface PolicySchemaStatus {
  sql_capabilities_writable: boolean;
  latched?: boolean;
  evidence_ready?: boolean;
  reason?: string | null;
  membership?: string;
  nodes?: PolicySchemaNode[];
}

// ── effective privileges (resources/v2/sql/privileges/<resource>) ───────

export interface SqlObjectPrivileges {
  catalog: string;
  schema: string;
  object: string;
  addressable: boolean;
  capabilities: string[];
}

export interface SqlPrivileges {
  resource: string;
  server: string[];
  resource_wide: string[];
  objects?: SqlObjectPrivileges[];
}

/** `catalog/schema/object` as the `objects` query wants it: each name percent-encodes `/`, `,` and `%`. */
export function encodeSqlObjectTriple(catalog: string, schema: string, object: string): string {
  const enc = (s: string) => s.replace(/%/g, "%25").replace(/\//g, "%2F").replace(/,/g, "%2C");
  return [catalog, schema, object].map(enc).join("/");
}
