import { describe, it, expect } from "vitest";
import {
  DEFAULT_RESOURCE_TYPES,
  inferOsType,
  getTypeDef,
} from "../lib/resourceTypes";

describe("resource types — Resource Connect schema", () => {
  it("server type carries the structured os_type select alongside the free-form os field", () => {
    const server = DEFAULT_RESOURCE_TYPES["server"];
    expect(server).toBeDefined();
    const osType = server.fields.find((f) => f.key === "os_type");
    expect(osType?.type).toBe("select");
    const values = (osType?.options ?? []).map((o) => o.value);
    // Every value the Connect button dispatches on must be present.
    expect(values).toEqual(
      expect.arrayContaining([
        "",
        "linux",
        "windows",
        "macos",
        "bsd",
        "unix",
        "other",
      ]),
    );
    // Free-form `os` stays for human-readable distro/version.
    expect(server.fields.find((f) => f.key === "os")?.type).toBe("text");
  });

  it("firewall type carries vendor, HA role, and SSH-22 connect default", () => {
    const fw = DEFAULT_RESOURCE_TYPES["firewall"];
    expect(fw).toBeDefined();
    expect(fw.label).toBe("Firewall");
    const vendor = fw.fields.find((f) => f.key === "vendor");
    expect(vendor?.type).toBe("select");
    const vendorValues = (vendor?.options ?? []).map((o) => o.value);
    expect(vendorValues).toEqual(
      expect.arrayContaining([
        "fortinet",
        "palo_alto",
        "cisco",
        "checkpoint",
        "juniper",
        "sophos",
        "pfsense",
        "other",
      ]),
    );
    const ha = fw.fields.find((f) => f.key === "ha_role");
    expect(ha?.type).toBe("select");
    expect((ha?.options ?? []).map((o) => o.value)).toEqual(
      expect.arrayContaining(["standalone", "active", "passive"]),
    );
    expect(fw.connect?.enabled).toBe(true);
    expect(fw.connect?.default_ports?.ssh).toBe(22);
  });

  it("switch type carries vendor, layer, and SSH-22 connect default", () => {
    const sw = DEFAULT_RESOURCE_TYPES["switch"];
    expect(sw).toBeDefined();
    expect(sw.label).toBe("Switch");
    const vendor = sw.fields.find((f) => f.key === "vendor");
    expect(vendor?.type).toBe("select");
    expect((vendor?.options ?? []).map((o) => o.value)).toEqual(
      expect.arrayContaining([
        "cisco",
        "arista",
        "juniper",
        "hpe_aruba",
        "huawei",
        "mikrotik",
        "ubiquiti",
        "other",
      ]),
    );
    const layer = sw.fields.find((f) => f.key === "switch_layer");
    expect(layer?.type).toBe("select");
    expect((layer?.options ?? []).map((o) => o.value)).toEqual(
      expect.arrayContaining(["l2", "l3"]),
    );
    expect(sw.connect?.enabled).toBe(true);
    expect(sw.connect?.default_ports?.ssh).toBe(22);
  });

  it("database engine is a closed enum covering the canonical engines", () => {
    const db = DEFAULT_RESOURCE_TYPES["database"];
    const engine = db.fields.find((f) => f.key === "engine");
    expect(engine?.type).toBe("select");
    expect((engine?.options ?? []).map((o) => o.value)).toEqual(
      expect.arrayContaining([
        "postgresql",
        "mysql",
        "mariadb",
        "mssql",
        "oracle",
        "mongodb",
        "redis",
        "elasticsearch",
        "sqlite",
        "other",
      ]),
    );
    expect(db.fields.find((f) => f.key === "engine_version")?.type).toBe("text");
    expect(db.fields.find((f) => f.key === "tls_required")?.type).toBe("select");
  });

  it("network_device stays as the catch-all (no firewall/switch in the placeholder)", () => {
    const nd = DEFAULT_RESOURCE_TYPES["network_device"];
    expect(nd).toBeDefined();
    const dt = nd.fields.find((f) => f.key === "device_type");
    expect(dt?.type).toBe("text");
    expect(dt?.placeholder ?? "").not.toMatch(/switch/i);
    expect(dt?.placeholder ?? "").not.toMatch(/firewall/i);
  });

  it("getTypeDef on an unknown id returns a generic placeholder", () => {
    const td = getTypeDef(DEFAULT_RESOURCE_TYPES, "definitely-not-a-type");
    expect(td.id).toBe("definitely-not-a-type");
    expect(td.fields).toEqual([]);
  });
});

describe("inferOsType — migration heuristic", () => {
  it("recognises common Linux distros", () => {
    expect(inferOsType("Ubuntu 24.04")).toBe("linux");
    expect(inferOsType("Debian 12")).toBe("linux");
    expect(inferOsType("RHEL 9.4")).toBe("linux");
    expect(inferOsType("AlmaLinux 9")).toBe("linux");
    expect(inferOsType("Amazon Linux 2023")).toBe("linux");
    expect(inferOsType("Alpine 3.20")).toBe("linux");
    expect(inferOsType("NixOS 24.05")).toBe("linux");
  });

  it("recognises Windows variants", () => {
    expect(inferOsType("Windows Server 2022")).toBe("windows");
    expect(inferOsType("Windows 11 Pro")).toBe("windows");
    expect(inferOsType("Server 2019")).toBe("windows");
    expect(inferOsType("Win 10")).toBe("windows");
  });

  it("recognises macOS spellings", () => {
    expect(inferOsType("macOS Sequoia")).toBe("macos");
    expect(inferOsType("Mac OS 14")).toBe("macos");
    expect(inferOsType("Darwin 23.5")).toBe("macos");
    expect(inferOsType("OSX 10.14")).toBe("macos");
  });

  it("recognises BSD variants", () => {
    expect(inferOsType("FreeBSD 14")).toBe("bsd");
    expect(inferOsType("OpenBSD 7.5")).toBe("bsd");
    expect(inferOsType("NetBSD 10")).toBe("bsd");
  });

  it("recognises legacy Unix variants as `unix`", () => {
    expect(inferOsType("Solaris 11")).toBe("unix");
    expect(inferOsType("AIX 7.3")).toBe("unix");
    expect(inferOsType("HP-UX 11")).toBe("unix");
  });

  it("returns empty when nothing matches", () => {
    expect(inferOsType("")).toBe("");
    expect(inferOsType("    ")).toBe("");
    expect(inferOsType("some custom appliance OS")).toBe("");
  });

  it("never overrides a value the heuristic isn't confident about", () => {
    // 'server' on its own (not 'Server YYYY') shouldn't trigger
    // Windows — too many non-Windows things called 'server'.
    expect(inferOsType("server")).toBe("");
  });
});
