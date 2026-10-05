import type { ConnectProtocol, ResourceTypeDef, ResourceTypeConfig, WebExposure } from "./types";

/** Default built-in resource types with their fields. */
export const DEFAULT_RESOURCE_TYPES: ResourceTypeConfig = {
  server: {
    id: "server",
    label: "Server",
    color: "info",
    icon: "Server",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "web01.example.com" },
      { key: "ip_address", label: "IP Address", type: "ip", placeholder: "10.0.1.50" },
      { key: "port", label: "Port", type: "number", placeholder: "22" },
      // Structured OS family — drives the GUI's Connect button
      // (SSH for *nix; RDP for Windows). The free-form `os` field
      // below stays as the human-readable distro/version. See
      // features/resource-connect.md.
      {
        key: "os_type",
        label: "OS Type",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "linux", label: "Linux" },
          { value: "windows", label: "Windows" },
          { value: "macos", label: "macOS" },
          { value: "bsd", label: "BSD" },
          { value: "unix", label: "Other Unix" },
          { value: "other", label: "Other / unknown" },
        ],
      },
      { key: "os", label: "OS", type: "text", placeholder: "Ubuntu 24.04" },
      { key: "location", label: "Location", type: "text", placeholder: "us-east-1" },
      { key: "owner", label: "Owner", type: "text", placeholder: "infra-team" },
    ],
  },
  database: {
    id: "database",
    label: "Database",
    color: "error",
    icon: "Database",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "db01.example.com" },
      { key: "ip_address", label: "IP Address", type: "ip", placeholder: "10.0.2.10" },
      { key: "port", label: "Port", type: "number", placeholder: "5432" },
      {
        key: "engine",
        label: "Engine",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "postgresql", label: "PostgreSQL" },
          { value: "mysql", label: "MySQL" },
          { value: "mariadb", label: "MariaDB" },
          { value: "mssql", label: "Microsoft SQL Server" },
          { value: "oracle", label: "Oracle Database" },
          { value: "mongodb", label: "MongoDB" },
          { value: "redis", label: "Redis" },
          { value: "elasticsearch", label: "Elasticsearch / OpenSearch" },
          { value: "sqlite", label: "SQLite" },
          { value: "other", label: "Other" },
        ],
      },
      { key: "engine_version", label: "Engine Version", type: "text", placeholder: "16.2" },
      { key: "database_name", label: "Database Name", type: "text", placeholder: "myapp_production" },
      {
        key: "tls_required",
        label: "TLS Required",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "yes", label: "Yes" },
          { value: "no", label: "No" },
        ],
      },
      { key: "owner", label: "Owner", type: "text", placeholder: "dba-team" },
    ],
  },
  firewall: {
    id: "firewall",
    label: "Firewall",
    color: "error",
    icon: "ShieldCheck",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "fw-edge-01" },
      { key: "ip_address", label: "Management IP", type: "ip", placeholder: "10.0.0.1" },
      { key: "port", label: "Mgmt Port", type: "number", placeholder: "22" },
      {
        key: "vendor",
        label: "Vendor",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "fortinet", label: "Fortinet" },
          { value: "palo_alto", label: "Palo Alto" },
          { value: "cisco", label: "Cisco" },
          { value: "checkpoint", label: "Check Point" },
          { value: "juniper", label: "Juniper" },
          { value: "sophos", label: "Sophos" },
          { value: "pfsense", label: "pfSense / OPNsense" },
          { value: "other", label: "Other" },
        ],
      },
      { key: "model", label: "Model", type: "text", placeholder: "FortiGate 100F" },
      { key: "firmware", label: "Firmware", type: "text", placeholder: "FortiOS 7.4.3" },
      {
        key: "ha_role",
        label: "HA Role",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "standalone", label: "Standalone" },
          { value: "active", label: "HA — Active" },
          { value: "passive", label: "HA — Passive" },
        ],
      },
      { key: "site", label: "Site / Zone", type: "text", placeholder: "DC-1 / DMZ" },
      { key: "owner", label: "Owner", type: "text", placeholder: "network-security" },
    ],
    connect: { enabled: true, default_ports: { ssh: 22 } },
  },
  switch: {
    id: "switch",
    label: "Switch",
    color: "warning",
    icon: "Network",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "sw-core-01" },
      { key: "ip_address", label: "Management IP", type: "ip", placeholder: "10.0.0.2" },
      { key: "port", label: "Mgmt Port", type: "number", placeholder: "22" },
      {
        key: "vendor",
        label: "Vendor",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "cisco", label: "Cisco" },
          { value: "arista", label: "Arista" },
          { value: "juniper", label: "Juniper" },
          { value: "hpe_aruba", label: "HPE Aruba" },
          { value: "huawei", label: "Huawei" },
          { value: "mikrotik", label: "MikroTik" },
          { value: "ubiquiti", label: "Ubiquiti" },
          { value: "other", label: "Other" },
        ],
      },
      { key: "model", label: "Model", type: "text", placeholder: "Catalyst 9300" },
      { key: "firmware", label: "Firmware / OS", type: "text", placeholder: "IOS-XE 17.12.1" },
      {
        key: "switch_layer",
        label: "Layer",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "l2", label: "L2 (access / distribution)" },
          { value: "l3", label: "L3 (core / routed)" },
        ],
      },
      { key: "stack_member_count", label: "Stack Members", type: "number", placeholder: "1" },
      { key: "location", label: "Location", type: "text", placeholder: "DC-1 Rack A3" },
      { key: "owner", label: "Owner", type: "text", placeholder: "network-team" },
    ],
    connect: { enabled: true, default_ports: { ssh: 22 } },
  },
  network_device: {
    id: "network_device",
    label: "Network Device",
    color: "warning",
    icon: "Router",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "rtr-edge-01" },
      { key: "ip_address", label: "Management IP", type: "ip", placeholder: "10.0.0.1" },
      { key: "device_type", label: "Device Type", type: "text", placeholder: "Router / Load Balancer / Wireless" },
      { key: "manufacturer", label: "Manufacturer", type: "text", placeholder: "Cisco" },
      { key: "model", label: "Model", type: "text", placeholder: "ASR 1001-X" },
      { key: "location", label: "Location", type: "text", placeholder: "DC-1 Rack A3" },
      { key: "owner", label: "Owner", type: "text", placeholder: "network-team" },
    ],
  },
  website: {
    id: "website",
    label: "Website",
    color: "success",
    icon: "Globe",
    fields: [
      { key: "url", label: "URL", type: "url", placeholder: "https://example.com" },
      { key: "hostname", label: "Server", type: "fqdn", placeholder: "web01.example.com" },
      { key: "technology", label: "Technology", type: "text", placeholder: "React / Django / Rails" },
      { key: "owner", label: "Owner", type: "text", placeholder: "dev-team" },
    ],
    // Web Application Connect (T96): a website opens in an in-app web
    // session window. Only reaches deployments whose saved type config has
    // no `website` entry — a saved type is never altered by a release.
    // `web_exposure_max: "dom"` opts the type in to form-mode logins: the
    // server releases no web credential unless the resource's saved type
    // sets a cap (deny unless opted in, spec §6).
    connect: { protocols: ["web"], web_exposure_max: "dom" },
  },
  web_application: {
    id: "web_application",
    label: "Web Application",
    color: "info",
    icon: "Globe",
    fields: [
      { key: "url", label: "URL", type: "url", placeholder: "https://fw01.example.com/" },
      {
        key: "vendor",
        label: "Vendor",
        type: "select",
        options: [
          { value: "", label: "(unset)" },
          { value: "generic", label: "Generic" },
          { value: "fortigate", label: "FortiGate" },
          { value: "vcenter", label: "VMware vCenter" },
          { value: "idrac", label: "Dell iDRAC" },
          { value: "ilo", label: "HPE iLO" },
          { value: "pfsense", label: "pfSense / OPNsense" },
          { value: "grafana", label: "Grafana" },
          { value: "jenkins", label: "Jenkins" },
          { value: "other", label: "Other" },
        ],
      },
      { key: "environment", label: "Environment", type: "text", placeholder: "production" },
      { key: "owner", label: "Owner", type: "text", placeholder: "network-team" },
    ],
    // Opted in to form-mode logins (see `website` above).
    connect: { protocols: ["web"], web_exposure_max: "dom" },
  },
  application: {
    id: "application",
    label: "Application",
    color: "neutral",
    icon: "AppWindow",
    fields: [
      { key: "hostname", label: "Server", type: "fqdn", placeholder: "app01.example.com" },
      { key: "port", label: "Port", type: "number", placeholder: "8080" },
      { key: "technology", label: "Technology", type: "text", placeholder: "Java / Node.js / Go" },
      { key: "repository", label: "Repository", type: "url", placeholder: "https://github.com/..." },
      { key: "owner", label: "Owner", type: "text", placeholder: "dev-team" },
    ],
  },
};

// ── Saved type config: additive merge with tombstones ───────────────
//
// The type config is one opaque JSON object at the resource mount's
// `config/types`, keyed by type id. Until T96 a saved config *replaced*
// the defaults, so a deployment that had ever saved its types never saw a
// new builtin. The merge is now additive: saved types win per key, and
// builtins the saved config lacks are added — unless the operator deleted
// them, which is recorded as a tombstone.
//
// Where the tombstone lives. Older GUIs read the blob as
// `Record<string, ResourceTypeDef>` and iterate every value, touching
// `.id`, `.label`, `.color` and `.fields.length`. A bare top-level array
// would crash them. So the tombstone is a reserved entry shaped like a
// type definition — `fields: []`, Connect disabled — under a key that
// Settings can never mint as a type id (`$` is not in `[a-z0-9_]`), written
// last so it is never an older GUI's default pick, and written only when
// at least one builtin has been deleted. An older GUI shows it as an extra
// type named "(internal) removed built-in types"; it round-trips it
// untouched through its own saves, so the tombstones survive.

/** Reserved key of the tombstone entry in the saved type config. */
export const TYPE_CONFIG_META_KEY = "$bv_meta";

/**
 * Builtins that existed before tombstones did. A config saved by an older
 * GUI that lacks one of these was saved by a GUI that offered it — so the
 * operator deleted it. Without a tombstone entry those absences are read as
 * deletions, not as builtins to add. Frozen: a builtin added later is
 * absent from such a config because it is *new*, and must be added.
 */
export const PRE_TOMBSTONE_BUILTIN_IDS: readonly string[] = Object.freeze([
  "server",
  "database",
  "firewall",
  "switch",
  "network_device",
  "website",
  "application",
]);

/** A saved type config, split into the types and the tombstones. */
export interface ParsedTypeConfig {
  /** Every type to show: saved ones plus builtins the merge added. */
  types: ResourceTypeConfig;
  /** Builtin ids the operator deleted; never re-added by the merge. */
  removedBuiltins: string[];
}

function readTombstones(meta: unknown): string[] | null {
  if (typeof meta !== "object" || meta === null) return null;
  const raw = (meta as { removed_builtins?: unknown }).removed_builtins;
  if (!Array.isArray(raw)) return [];
  return raw.filter((v): v is string => typeof v === "string");
}

/**
 * Parse a saved type config (the `resource_types_read` payload).
 *
 * * `null` (never saved) → the builtins, no tombstones.
 * * Saved types are kept verbatim, per key.
 * * A builtin absent from the saved config is added unless it is
 *   tombstoned — explicitly, or implicitly for a pre-tombstone save (see
 *   {@link PRE_TOMBSTONE_BUILTIN_IDS}).
 */
export function parseTypeConfig(saved: Record<string, unknown> | null): ParsedTypeConfig {
  if (!saved) return { types: { ...DEFAULT_RESOURCE_TYPES }, removedBuiltins: [] };
  const types: ResourceTypeConfig = {};
  for (const [id, def] of Object.entries(saved)) {
    if (id === TYPE_CONFIG_META_KEY) continue;
    types[id] = def as ResourceTypeDef;
  }
  const explicit = readTombstones(saved[TYPE_CONFIG_META_KEY]);
  const removed = new Set<string>(explicit ?? []);
  if (explicit === null) {
    for (const id of PRE_TOMBSTONE_BUILTIN_IDS) {
      if (!(id in types)) removed.add(id);
    }
  }
  for (const [id, def] of Object.entries(DEFAULT_RESOURCE_TYPES)) {
    if (id in types || removed.has(id)) continue;
    types[id] = def;
  }
  const removedBuiltins = [...removed]
    .filter((id) => id in DEFAULT_RESOURCE_TYPES && !(id in types))
    .sort();
  return { types, removedBuiltins };
}

/**
 * Build the object to write back to `config/types`. The tombstone entry is
 * appended last and only when there is something in it.
 */
export function serializeTypeConfig(
  types: ResourceTypeConfig,
  removedBuiltins: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [id, def] of Object.entries(types)) {
    if (id === TYPE_CONFIG_META_KEY) continue;
    out[id] = def;
  }
  const tombstones = [...new Set(removedBuiltins)]
    .filter((id) => id in DEFAULT_RESOURCE_TYPES && !(id in types))
    .sort();
  if (tombstones.length > 0) {
    out[TYPE_CONFIG_META_KEY] = {
      id: TYPE_CONFIG_META_KEY,
      label: "(internal) removed built-in types",
      color: "neutral",
      fields: [],
      connect: { enabled: false },
      removed_builtins: tombstones,
    };
  }
  return out;
}

/** Saved config merged with the builtins — the types to show. */
export function mergeTypeConfig(saved: ResourceTypeConfig | null): ResourceTypeConfig {
  return parseTypeConfig(saved as Record<string, unknown> | null).types;
}

// ── Connect protocols ────────────────────────────────────────────────

const CONNECT_PROTOCOLS: readonly ConnectProtocol[] = ["ssh", "rdp", "web"];

function isConnectProtocol(v: unknown): v is ConnectProtocol {
  return typeof v === "string" && (CONNECT_PROTOCOLS as readonly string[]).includes(v);
}

/**
 * The type that offered SSH/RDP Connect before `connect.protocols` existed.
 * Absent `protocols` keeps that exact behaviour: `server` offers SSH and
 * RDP, every other type offers nothing.
 */
const LEGACY_CONNECT_TYPE_ID = "server";

/**
 * The Connect protocols a resource type offers — the single gate for the
 * Connect chip, the Connection tab, the ⌘K palette and the profile editor.
 *
 * * `connect.enabled === false` → none.
 * * `connect.protocols` set → those, with unknown entries dropped (a value
 *   this build doesn't know is never read as one it does) and a non-array
 *   read as none.
 * * absent → the legacy rule above.
 */
export function connectProtocols(typeDef: ResourceTypeDef | undefined | null): ConnectProtocol[] {
  if (!typeDef || typeDef.connect?.enabled === false) return [];
  const declared: unknown = typeDef.connect?.protocols;
  if (declared !== undefined) {
    if (!Array.isArray(declared)) return [];
    return CONNECT_PROTOCOLS.filter((p) => declared.some((d) => isConnectProtocol(d) && d === p));
  }
  return typeDef.id === LEGACY_CONNECT_TYPE_ID ? ["ssh", "rdp"] : [];
}

// ── Web exposure policy (spec §6) ───────────────────────────────────

/** The exposure caps a type can set, least to most exposed. */
export const WEB_EXPOSURE_CAPS: readonly WebExposure[] = ["none", "isolated", "handler", "proxy", "dom"];

/** The Settings control's value for `connect.web_exposure_max`: `""` is
 *  unset (the server then caps at `none`, so a credential-releasing login is
 *  denied), `"keep"` leaves a saved value this build does not recognise
 *  untouched. */
export type WebExposureChoice = WebExposure | "" | "keep";
/** Same for `connect.allow_heuristic_fill`. */
export type HeuristicChoice = "true" | "false" | "" | "keep";

/** Read the saved `connect.web_exposure_max` as a Settings choice. */
export function webExposureChoice(connect: ResourceTypeDef["connect"]): WebExposureChoice {
  const v: unknown = connect?.web_exposure_max;
  if (v === undefined || v === null) return "";
  return typeof v === "string" && (WEB_EXPOSURE_CAPS as readonly string[]).includes(v)
    ? (v as WebExposure)
    : "keep";
}

/** Read the saved `connect.allow_heuristic_fill` as a Settings choice. */
export function heuristicChoice(connect: ResourceTypeDef["connect"]): HeuristicChoice {
  const v: unknown = connect?.allow_heuristic_fill;
  if (v === undefined || v === null) return "";
  return v === true ? "true" : v === false ? "false" : "keep";
}

/**
 * Write the two policy choices onto a type's `connect` block. An unset choice
 * removes the key (so a saved config only carries what an administrator set),
 * and `"keep"` leaves whatever is saved — a value an administrator or a newer
 * build wrote is never silently rewritten by saving something unrelated.
 */
export function withWebPolicy(
  connect: NonNullable<ResourceTypeDef["connect"]>,
  exposure: WebExposureChoice,
  heuristic: HeuristicChoice,
): NonNullable<ResourceTypeDef["connect"]> {
  const out = { ...connect };
  if (exposure !== "keep") {
    if (exposure === "") delete out.web_exposure_max;
    else out.web_exposure_max = exposure;
  }
  if (heuristic !== "keep") {
    if (heuristic === "") delete out.allow_heuristic_fill;
    else out.allow_heuristic_fill = heuristic === "true";
  }
  return out;
}

/** True when the type offers `protocol`. */
export function typeSupportsProtocol(
  typeDef: ResourceTypeDef | undefined | null,
  protocol: ConnectProtocol,
): boolean {
  return connectProtocols(typeDef).includes(protocol);
}

/** True when the type offers any Connect protocol at all. */
export function typeSupportsConnect(typeDef: ResourceTypeDef | undefined | null): boolean {
  return connectProtocols(typeDef).length > 0;
}

/**
 * Heuristic mapping from a free-form `os` string (e.g. "Ubuntu
 * 24.04", "Windows Server 2022", "macOS Sequoia") to the structured
 * `os_type` enum used by the Connect button. Returns the empty
 * string when no confident match exists — the operator picks
 * manually in that case.
 */
export function inferOsType(osText: string): string {
  const s = osText.toLowerCase();
  if (!s.trim()) return "";
  if (/\bwin(dows)?\b/.test(s) || /\bserver\s*\d{4}\b/.test(s)) return "windows";
  if (/\bmac\s*os\b|\bmacos\b|\bdarwin\b|\bosx\b/.test(s)) return "macos";
  if (/\b(free|open|net|dragonfly)bsd\b/.test(s)) return "bsd";
  // No `\b` on the right because compound names ("AlmaLinux",
  // "RockyLinux", "OracleLinux") commonly run the distro and the
  // word "linux" together with no separator.
  if (
    /\b(linux|ubuntu|debian|rhel|red\s*hat|centos|fedora|alma|rocky|suse|amzn|amazon\s*linux|alpine|arch|gentoo|nixos|kali|mint|oracle\s*linux)/.test(
      s,
    )
  )
    return "linux";
  if (/\b(solaris|aix|hp-?ux|illumos|smartos)\b/.test(s)) return "unix";
  return "";
}

/** Get a type definition, falling back to a generic type. */
export function getTypeDef(types: ResourceTypeConfig, typeId: string): ResourceTypeDef {
  return types[typeId] ?? {
    id: typeId,
    label: typeId,
    color: "neutral",
    fields: [],
  };
}
