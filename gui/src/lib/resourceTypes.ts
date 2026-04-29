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
      { key: "engine", label: "Engine", type: "text", placeholder: "PostgreSQL 16" },
      { key: "database_name", label: "Database Name", type: "text", placeholder: "myapp_production" },
      { key: "owner", label: "Owner", type: "text", placeholder: "dba-team" },
    ],
  },
  network_device: {
    id: "network_device",
    label: "Network Device",
    color: "warning",
    fields: [
      { key: "hostname", label: "Hostname", type: "fqdn", placeholder: "sw-core-01" },
      { key: "ip_address", label: "Management IP", type: "ip", placeholder: "10.0.0.1" },
      { key: "device_type", label: "Device Type", type: "text", placeholder: "Switch / Router / Firewall" },
      { key: "manufacturer", label: "Manufacturer", type: "text", placeholder: "Cisco" },
      { key: "model", label: "Model", type: "text", placeholder: "Catalyst 9300" },
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
