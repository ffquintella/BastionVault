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

/** Get a type definition, falling back to a generic type. */
export function getTypeDef(types: ResourceTypeConfig, typeId: string): ResourceTypeDef {
  return types[typeId] ?? {
    id: typeId,
    label: typeId,
    color: "neutral",
    fields: [],
  };
}
