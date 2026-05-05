import type { ResourceTypeDef, ResourceTypeConfig } from "./types";

/** Default built-in resource types with their fields. */
export const DEFAULT_RESOURCE_TYPES: ResourceTypeConfig = {
  server: {
    id: "server",
    label: "Server",
    color: "info",
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
    fields: [
      { key: "url", label: "URL", type: "url", placeholder: "https://example.com" },
      { key: "hostname", label: "Server", type: "fqdn", placeholder: "web01.example.com" },
      { key: "technology", label: "Technology", type: "text", placeholder: "React / Django / Rails" },
      { key: "owner", label: "Owner", type: "text", placeholder: "dev-team" },
    ],
  },
  application: {
    id: "application",
    label: "Application",
    color: "neutral",
    fields: [
      { key: "hostname", label: "Server", type: "fqdn", placeholder: "app01.example.com" },
      { key: "port", label: "Port", type: "number", placeholder: "8080" },
      { key: "technology", label: "Technology", type: "text", placeholder: "Java / Node.js / Go" },
      { key: "repository", label: "Repository", type: "url", placeholder: "https://github.com/..." },
      { key: "owner", label: "Owner", type: "text", placeholder: "dev-team" },
    ],
  },
};

/** Merge saved config with defaults — saved types take precedence. */
export function mergeTypeConfig(saved: ResourceTypeConfig | null): ResourceTypeConfig {
  if (!saved) return { ...DEFAULT_RESOURCE_TYPES };
  // Saved config fully replaces defaults
  return saved;
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
