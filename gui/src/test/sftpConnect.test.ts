/**
 * SFTP connection profiles and the dual-pane window's pure helpers
 * (features/sftp-connect.md).
 */
import { describe, expect, it } from "vitest";

import {
  blankProfile,
  defaultPort,
  isLaunchableForCaller,
  isLaunchableProfile,
  isSshTransport,
  validateProfile,
  validateProfileForLoginClass,
} from "../lib/connectionProfiles";
import { providersForProtocol } from "../lib/credentialProviders";
import type { SftpEntry } from "../lib/api";
import {
  existsConflict,
  filterEntries,
  formatPermissions,
  formatSize,
  isValidEntryName,
  joinPath,
  newTransferId,
  parentPath,
  pathSegments,
  sortEntries,
} from "../lib/sftpPanes";
import type { ConnectionProfile } from "../lib/types";

function sftpProfile(cs: ConnectionProfile["credential_source"], extra: Partial<ConnectionProfile> = {}) {
  return { ...blankProfile("linux"), name: "files", protocol: "sftp", credential_source: cs, ...extra } as ConnectionProfile;
}

describe("sftp profiles", () => {
  it("ride the SSH transport and default to port 22", () => {
    expect(isSshTransport("sftp")).toBe(true);
    expect(isSshTransport("ssh")).toBe(true);
    expect(isSshTransport("rdp")).toBe(false);
    expect(defaultPort("sftp")).toBe(22);
  });

  it("launch with the SSH credential sources", () => {
    for (const cs of [
      { kind: "secret", secret_id: "login" },
      { kind: "ldap", ldap_mount: "ldap", bind_mode: "operator" },
      { kind: "pki", pki_mount: "pki", pki_role: "r" },
      { kind: "ssh-engine", ssh_mount: "ssh", ssh_role: "r", mode: "ca" },
    ] as ConnectionProfile["credential_source"][]) {
      const p = sftpProfile(cs);
      expect(validateProfile(p), cs.kind).toBeNull();
      expect(isLaunchableProfile(p), cs.kind).toBe(true);
    }
    // FIDO2 authenticates the SSH transport, so SFTP too.
    expect(validateProfile(sftpProfile({ kind: "fido2" } as ConnectionProfile["credential_source"]))).toBeNull();
  });

  it("refuse a credential provider, which has no SFTP release path", () => {
    const p = sftpProfile({ kind: "provider", provider: "self-accounts" } as ConnectionProfile["credential_source"]);
    expect(validateProfile(p)).toMatch(/can't use a credential provider/);
    expect(isLaunchableProfile(p)).toBe(false);
    expect(providersForProtocol([{ name: "self-accounts", protocols: ["ssh", "rdp"] }] as never, "sftp")).toEqual([]);
  });

  it("are direct-only: a rustion profile and a connect-only caller cannot launch one", () => {
    const secret = { kind: "secret", secret_id: "login" } as ConnectionProfile["credential_source"];
    expect(isLaunchableProfile(sftpProfile(secret, { kind: "rustion" }))).toBe(false);
    // A connect-only caller may launch only server-resolved, brokered SSH;
    // SFTP always resolves the credential onto this machine.
    expect(isLaunchableForCaller(sftpProfile(secret), true, true)).toBe(false);
    expect(isLaunchableForCaller(sftpProfile(secret), false, false)).toBe(true);
  });

  it("follow the SSH login-class rule on a brokered resource", () => {
    const secret = sftpProfile({ kind: "secret", secret_id: "login" } as ConnectionProfile["credential_source"]);
    expect(validateProfileForLoginClass(secret, "brokered")).toMatch(/brokered/);
    const minted = sftpProfile({ kind: "ssh-engine", ssh_mount: "ssh", ssh_role: "r", mode: "ca" } as ConnectionProfile["credential_source"]);
    expect(validateProfileForLoginClass(minted, "brokered")).toBeNull();
  });
});

const e = (name: string, kind: SftpEntry["kind"], size = 0, mtime: number | null = null): SftpEntry => ({
  name,
  kind,
  target_kind: kind,
  size,
  mtime,
  permissions: null,
});

describe("sftp pane paths", () => {
  it("join, split and climb POSIX paths", () => {
    expect(joinPath("/home/op", "f")).toBe("/home/op/f");
    expect(joinPath("/", "f")).toBe("/f");
    expect(parentPath("/home/op")).toBe("/home");
    expect(parentPath("/home")).toBe("/");
    expect(parentPath("/")).toBeNull();
    expect(pathSegments("/home/op").map((s) => s.path)).toEqual(["/", "/home", "/home/op"]);
  });

  it("join, split and climb Windows drive paths", () => {
    expect(joinPath("C:\\Users", "op")).toBe("C:\\Users\\op");
    expect(joinPath("C:\\", "op")).toBe("C:\\op");
    expect(parentPath("C:\\Users\\op")).toBe("C:\\Users");
    expect(parentPath("C:\\Users")).toBe("C:\\");
    expect(parentPath("C:\\")).toBeNull();
    expect(pathSegments("C:\\Users\\op").map((s) => s.label)).toEqual(["C:", "Users", "op"]);
  });
});

describe("sftp pane listing", () => {
  it("puts folders first and sorts names naturally", () => {
    const sorted = sortEntries([e("b10", "file"), e("b2", "file"), e("z", "dir"), e("a", "file")], {
      key: "name",
      asc: true,
    });
    expect(sorted.map((x) => x.name)).toEqual(["z", "a", "b2", "b10"]);
  });

  it("sorts by size and date within files", () => {
    const list = [e("a", "file", 30, 1), e("b", "file", 10, 3), e("c", "file", 20, 2)];
    expect(sortEntries(list, { key: "size", asc: true }).map((x) => x.name)).toEqual(["b", "c", "a"]);
    expect(sortEntries(list, { key: "date", asc: false }).map((x) => x.name)).toEqual(["b", "c", "a"]);
  });

  it("hides dotfiles unless asked and filters by name", () => {
    const list = [e(".ssh", "dir"), e("Report.pdf", "file"), e("notes", "file")];
    expect(filterEntries(list, "", false).map((x) => x.name)).toEqual(["Report.pdf", "notes"]);
    expect(filterEntries(list, "", true)).toHaveLength(3);
    expect(filterEntries(list, "rep", false).map((x) => x.name)).toEqual(["Report.pdf"]);
  });

  it("formats sizes and permissions", () => {
    expect(formatSize(512)).toBe("512 B");
    expect(formatSize(61_440)).toBe("60 KB");
    expect(formatSize(7.6 * 1024 * 1024)).toBe("7.6 MB");
    expect(formatPermissions(0o100755)).toBe("rwxr-xr-x");
    expect(formatPermissions(null)).toBe("");
  });
});

describe("sftp pane input", () => {
  it("accepts only single, safe names", () => {
    for (const bad of ["", ".", "..", "a/b", "a\\b", "x\0"]) expect(isValidEntryName(bad), bad).toBe(false);
    for (const ok of ["a", ".env", "ação.txt"]) expect(isValidEntryName(ok), ok).toBe(true);
  });

  it("reads the host's exists refusal", () => {
    expect(existsConflict("exists: report.pdf")).toBe("report.pdf");
    expect(existsConflict("sftp: permission denied")).toBeNull();
  });

  it("mints transfer ids the host accepts", () => {
    const a = newTransferId();
    expect(a).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    expect(newTransferId()).not.toBe(a);
  });
});
