/**
 * SMB connection profiles (features/smb-connect.md): the profile model and
 * its validation, the launch dispatch, the resource-type gate, the profile
 * editor, and the dual-pane window helpers the SMB side adds.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import {
  blankProfile,
  defaultPort,
  isLaunchableForCaller,
  isLaunchableProfile,
  isSshTransport,
  isValidSmbShareName,
  needsOperatorPrompt,
  parseSessionProtocol,
  readProfiles,
  readUnknownProfiles,
  validateProfile,
  validateProfileForLoginClass,
} from "../lib/connectionProfiles";
import { providersForProtocol } from "../lib/credentialProviders";
import { connectProtocols } from "../lib/resourceTypes";
import { openProfileSession } from "../lib/sessionLaunch";
import { isValidRemoteName, isWindowsFileName, remotePaneTitle, sessionHost } from "../lib/sftpPanes";
import type { ConnectionProfile, ResourceTypeDef } from "../lib/types";
import { ToastProvider } from "../components/ui/Toast";

function smbProfile(extra: Partial<ConnectionProfile> = {}): ConnectionProfile {
  return {
    ...blankProfile("windows"),
    name: "files",
    protocol: "smb",
    share: "files",
    credential_source: { kind: "secret", secret_id: "login" },
    ...extra,
  } as ConnectionProfile;
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("smb profiles", () => {
  it("are their own protocol: port 445, not an SSH transport", () => {
    expect(parseSessionProtocol("smb")).toBe("smb");
    expect(parseSessionProtocol("SMB")).toBeNull();
    expect(parseSessionProtocol("cifs")).toBeNull();
    expect(defaultPort("smb")).toBe(445);
    expect(isSshTransport("smb")).toBe(false);
  });

  it("launch with the password sources only", () => {
    for (const cs of [
      { kind: "secret", secret_id: "login" },
      { kind: "ldap", ldap_mount: "ldap", bind_mode: "operator" },
      { kind: "default-account" },
    ] as ConnectionProfile["credential_source"][]) {
      const p = smbProfile({ credential_source: cs });
      expect(validateProfile(p), cs.kind).toBeNull();
      expect(isLaunchableProfile(p), cs.kind).toBe(true);
    }
    for (const cs of [
      { kind: "pki", pki_mount: "pki", pki_role: "r" },
      { kind: "ssh-engine", ssh_mount: "ssh", ssh_role: "r", mode: "ca" },
      { kind: "fido2" },
      { kind: "provider", provider: "self-accounts" },
      { kind: "none" },
    ] as ConnectionProfile["credential_source"][]) {
      const p = smbProfile({ credential_source: cs });
      expect(validateProfile(p), cs.kind).not.toBeNull();
      expect(isLaunchableProfile(p), cs.kind).toBe(false);
    }
    expect(providersForProtocol([{ name: "self-accounts", protocols: ["ssh", "rdp"] }] as never, "smb")).toEqual([]);
  });

  it("need a valid share name and accept an optional domain", () => {
    expect(validateProfile(smbProfile({ share: "" }))).toMatch(/Share name is required/);
    for (const bad of ["a/b", "\\\\host\\files", " files", "..", "x".repeat(81), "f*"]) {
      expect(isValidSmbShareName(bad), bad).toBe(false);
      expect(validateProfile(smbProfile({ share: bad })), bad).toMatch(/Share name/);
    }
    for (const ok of ["files", "Dept Data$", "C$"]) expect(isValidSmbShareName(ok), ok).toBe(true);
    expect(validateProfile(smbProfile({ domain: "CORP" }))).toBeNull();
    expect(validateProfile(smbProfile({ domain: "CORP\\x" }))).toMatch(/Domain/);
  });

  it("are direct-only and resolve their credential on this machine", () => {
    const rustion = smbProfile({ kind: "rustion" });
    expect(validateProfile(rustion)).toMatch(/Rustion/);
    expect(isLaunchableProfile(rustion)).toBe(false);
    // A connect-only caller may not pull a password onto this machine.
    expect(isLaunchableForCaller(smbProfile(), true, true)).toBe(false);
    expect(isLaunchableForCaller(smbProfile(), false, false)).toBe(true);
  });

  it("are refused on a brokered resource", () => {
    expect(validateProfileForLoginClass(smbProfile(), "brokered")).toMatch(/brokered/);
    expect(validateProfileForLoginClass(smbProfile(), "shared-credential")).toBeNull();
  });

  it("prompt for the password of a default account, as RDP does", () => {
    expect(needsOperatorPrompt(smbProfile({ credential_source: { kind: "default-account" } }))).toBe(true);
    expect(needsOperatorPrompt(smbProfile())).toBe(false);
  });

  /** A profile a client without SMB cannot read stays fail-closed: hidden
   *  from launch and kept verbatim on save. This build reads it. */
  it("parse strictly from storage", () => {
    const meta = {
      connection_profiles: [
        { id: "p1", name: "share", protocol: "smb", share: "files", credential_source: { kind: "secret", secret_id: "s" } },
        { id: "p2", name: "future", protocol: "nfs", credential_source: { kind: "secret", secret_id: "s" } },
      ],
    };
    expect(readProfiles(meta).map((p) => p.id)).toEqual(["p1"]);
    expect(readUnknownProfiles(meta)).toHaveLength(1);
  });
});

describe("smb launch", () => {
  it("dispatches to session_open_smb with no placement", async () => {
    mockInvoke.mockResolvedValue({});
    await openProfileSession(
      { protocol: "smb" },
      {
        resource_name: "fs01",
        profile_id: "p1",
        connect_ticket: "t",
        operator_credential: { username: "op", password: "pw" },
        placement: "workspace" as never,
      },
    );
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke.mock.calls[0][0]).toBe("session_open_smb");
    expect(mockInvoke.mock.calls[0][1]).toEqual({
      request: {
        resource_name: "fs01",
        profile_id: "p1",
        operator_credential: { username: "op", password: "pw" },
        connect_ticket: "t",
      },
    });
  });
});

describe("resource types offering smb", () => {
  const type = (def: Partial<ResourceTypeDef>) => ({ id: "x", label: "X", fields: [], ...def }) as ResourceTypeDef;

  it("the built-in server type offers it by default; a custom type only when it names it", () => {
    expect(connectProtocols(type({ id: "server" }))).toEqual(["ssh", "sftp", "smb", "rdp"]);
    expect(connectProtocols(type({ connect: { protocols: ["ssh", "rdp"] } }))).toEqual(["ssh", "rdp"]);
    expect(connectProtocols(type({ connect: { protocols: ["smb"] } }))).toEqual(["smb"]);
    expect(connectProtocols(type({ id: "server", connect: { protocols: ["ssh"] } }))).toEqual(["ssh"]);
  });
});

describe("smb window helpers", () => {
  it("apply Windows naming to names sent to the share", () => {
    for (const bad of ["a:b", "NUL", "con.txt", "COM1", "x?", "trail.", "trail ", "a/b", ".."]) {
      expect(isValidRemoteName("smb", bad), bad).toBe(false);
    }
    for (const ok of ["report.pdf", "CONSOLE", "COM10", "ação"]) expect(isValidRemoteName("smb", ok), ok).toBe(true);
    // SFTP keeps its POSIX rule.
    expect(isValidRemoteName("sftp", "a:b")).toBe(true);
    expect(isWindowsFileName("a:b")).toBe(false);
  });

  it("title the remote pane with the share", () => {
    expect(sessionHost("smb op@fs01:445/files")).toBe("op@fs01:445/files");
    expect(remotePaneTitle("smb", "smb op@fs01:445/files")).toBe("\\\\fs01\\files");
    expect(remotePaneTitle("sftp", "sftp op@srv:22")).toBe("srv");
    expect(remotePaneTitle("sftp", "sftp op@10.0.0.5:22 via rustion[edge-1]")).toBe("10.0.0.5");
  });
});

describe("profile editor with smb", () => {
  function mockEditorBackend() {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_resource_secrets":
          return Promise.resolve({ keys: ["login"] });
        case "resource_login_class":
          return Promise.resolve({
            login_class: "shared-credential",
            login_class_source: "default",
            login_class_chain: [],
            locked_at_tier: null,
          });
        case "connect_credential_providers":
          return Promise.resolve([]);
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
  }

  it("asks for the share, offers only password sources, has no host-key pin, and saves", async () => {
    mockEditorBackend();
    const onSave = vi.fn().mockResolvedValue(undefined);
    const { ConnectionProfileEditor } = await import("../routes/ResourcesPage");
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ConnectionProfileEditor
          open
          resource={{ name: "fs01", type: "server", hostname: "fs01.example.test", os_type: "windows" } as never}
          protocols={["ssh", "sftp", "smb", "rdp"]}
          existing={null}
          onClose={() => {}}
          onSave={onSave}
          toast={() => {}}
        />
      </ToastProvider>,
    );
    await user.selectOptions(screen.getByLabelText("Protocol"), "smb");
    expect(screen.getByLabelText("Share")).toBeInTheDocument();
    expect(screen.queryByLabelText("Host-key pin (optional)")).toBeNull();
    const sources = [...(screen.getByLabelText("Credential source") as HTMLSelectElement).options].map((o) => o.value);
    expect(sources.sort()).toEqual(["default-account", "ldap", "secret"]);

    const save = screen.getByRole("button", { name: "Save" });
    await waitFor(() => expect(screen.getByRole("option", { name: "login" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Resource secret"), "login");
    // The share is still empty: the editor holds the save.
    expect(save).toBeDisabled();
    await user.type(screen.getByLabelText("Share"), "files");
    await user.type(screen.getByLabelText("Domain (optional)"), "CORP");
    await waitFor(() => expect(save).toBeEnabled());
    await user.click(save);
    expect(onSave).toHaveBeenCalledTimes(1);
    const saved = onSave.mock.calls[0][0] as ConnectionProfile;
    expect(saved.protocol).toBe("smb");
    expect(saved.share).toBe("files");
    expect(saved.domain).toBe("CORP");
    expect(saved.credential_source).toEqual({ kind: "secret", secret_id: "login" });
    expect(saved.host_key_pin).toBeUndefined();
  });
});
