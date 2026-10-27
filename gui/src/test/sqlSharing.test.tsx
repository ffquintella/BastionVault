/**
 * Sharing UI: the eleven sql_* chips and the presets of features/sql-browser.md
 * §3.3, offered on resource and asset-group targets only.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { ObjectSharingCard } from "../components/ObjectSharingCard";
import { useAuthStore } from "../stores/authStore";
import type { ShareTargetKind } from "../lib/types";
import { SQL_CAPABILITIES } from "../lib/sqlPrivileges";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
}));

const GRANTEE = "33333333-3333-3333-3333-333333333333";
const GATE_409 =
  "Error response status 409: the share names sql_* capabilities, which cannot be written until every cluster " +
  "node parses them (policy schema 2, plugin host ABI 1.4): node 3: stale record. `v2/sys/policy-schema` reports each node";

function bridge(over: Record<string, (args?: unknown) => unknown> = {}) {
  mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
    if (over[cmd]) return over[cmd](args);
    if (cmd === "list_shares_for_target") return Promise.resolve([]);
    if (cmd === "list_entity_aliases") return Promise.resolve([]);
    if (cmd === "put_share") return Promise.resolve({});
    if (cmd === "policy_schema_status") return Promise.resolve({ sql_capabilities_writable: true });
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

async function openGrant(
  props: { kind: ShareTargetKind; noun: string; capabilities: string[] } & Partial<
    React.ComponentProps<typeof ObjectSharingCard>
  >,
  toast: (t: string, m: string) => void = () => {},
) {
  const user = userEvent.setup();
  render(
    <ToastProvider>
      <ObjectSharingCard
        target="netrisk-db"
        owner={{ transfer: async () => {} }}
        toast={toast}
        {...props}
      />
    </ToastProvider>,
  );
  await waitFor(() => expect(screen.queryByText(/loading sharing info/i)).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: /grant access/i }));
  await user.type(screen.getByPlaceholderText(/paste entity_id/i), GRANTEE);
  return user;
}

const RESOURCE = {
  kind: "resource" as const,
  noun: "resource",
  capabilities: ["read", "list", "update", "delete", "create", "connect"],
  sqlPrivileges: true,
  defaultCapabilities: ["sql_select"],
};

const pressed = (name: string | RegExp) => screen.getByRole("button", { name }).getAttribute("aria-pressed");

beforeEach(() => {
  mockInvoke.mockReset();
  bridge();
  useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "entity-1" });
});

describe("a database resource's grant form", () => {
  it("shows the eleven chips and the four presets, with Read only pre-selected", async () => {
    await openGrant(RESOURCE);
    const group = screen.getByTestId("sql-share-capabilities");
    for (const c of SQL_CAPABILITIES) expect(within(group).getByRole("button", { name: c })).toBeInTheDocument();
    const presets = within(screen.getByRole("group", { name: "SQL presets" })).getAllByRole("button");
    expect(presets.map((b) => b.textContent)).toEqual(["Read only", "Read/write", "Schema change", "Full"]);
    expect(pressed("Read only")).toBe("true");
    expect(pressed("Read/write")).toBe("false");
    expect(pressed("sql_select")).toBe("true");
  });

  it("does not suggest read on the secret: the form starts without it and says why", async () => {
    await openGrant(RESOURCE);
    expect(pressed("read")).toBe("false");
    expect(screen.getByTestId("sql-share-capabilities")).toHaveTextContent(/read on the resource reveals its stored secrets/);
    expect(screen.getByTestId("sql-share-capabilities")).toHaveTextContent(/not needed for the SQL browser/);
  });

  it("grants Read only by default, without read", async () => {
    const user = await openGrant(RESOURCE);
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("put_share", {
        kind: "resource",
        targetPath: "netrisk-db",
        grantee: GRANTEE,
        granteeKind: "entity",
        capabilities: ["sql_select"],
        expiresAt: "",
      }),
    );
  });

  it("applies a preset, keeps sql_export and sql_script as separate toggles, and leaves connect alone", async () => {
    const user = await openGrant(RESOURCE);
    await user.click(screen.getByRole("button", { name: "connect" }));
    await user.click(screen.getByRole("button", { name: "sql_export" }));
    await user.click(screen.getByRole("button", { name: "Schema change" }));
    expect(pressed("Schema change")).toBe("true");
    for (const c of ["sql_select", "sql_insert", "sql_update", "sql_delete", "sql_alter", "sql_create", "sql_drop"]) {
      expect(pressed(c)).toBe("true");
    }
    expect(pressed("sql_execute")).toBe("false");
    expect(pressed("sql_export")).toBe("true");
    expect(pressed("connect")).toBe("true");
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "put_share",
        expect.objectContaining({
          capabilities: [
            "connect",
            "sql_select",
            "sql_insert",
            "sql_update",
            "sql_delete",
            "sql_alter",
            "sql_create",
            "sql_drop",
            "sql_export",
          ],
        }),
      ),
    );
  });

  it("Full is everything except sql_export and sql_script", async () => {
    const user = await openGrant(RESOURCE);
    await user.click(screen.getByRole("button", { name: "Full" }));
    for (const c of SQL_CAPABILITIES) {
      expect(pressed(c)).toBe(c === "sql_export" || c === "sql_script" ? "false" : "true");
    }
  });

  it("drops the preset highlight once the selection no longer matches one", async () => {
    const user = await openGrant(RESOURCE);
    await user.click(screen.getByRole("button", { name: "sql_update" }));
    expect(pressed("Read only")).toBe("false");
    expect(pressed("Read/write")).toBe("false");
  });
});

describe("where the SQL chips are offered", () => {
  it("not on a resource that is not a database", async () => {
    await openGrant({ ...RESOURCE, sqlPrivileges: false, defaultCapabilities: ["read"] });
    expect(screen.queryByTestId("sql-share-capabilities")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "sql_select" })).not.toBeInTheDocument();
    expect(pressed("read")).toBe("true");
  });

  it("on an asset group, which keeps its own default", async () => {
    await openGrant({
      kind: "asset-group",
      noun: "group",
      capabilities: ["read", "list", "update", "delete", "create"],
      sqlPrivileges: true,
    });
    expect(screen.getByTestId("sql-share-capabilities")).toBeInTheDocument();
    expect(pressed("read")).toBe("true");
    expect(pressed("Read only")).toBe("false");
  });

  it.each<[ShareTargetKind, string]>([
    ["kv-secret", "KV path"],
    ["file", "file"],
  ])("never on a %s target, whatever is passed (the server refuses it with a 400)", async (kind, noun) => {
    await openGrant({ kind, noun, capabilities: ["read", "list", "update", "delete", "create"], sqlPrivileges: true });
    expect(screen.queryByTestId("sql-share-capabilities")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "sql_select" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Read only" })).not.toBeInTheDocument();
  });
});

describe("the sql_* write gate on a share", () => {
  it("turns the 409 into one clear message", async () => {
    bridge({ put_share: () => Promise.reject(new Error(GATE_409)) });
    const toast = vi.fn();
    const user = await openGrant(RESOURCE, toast);
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() => expect(toast).toHaveBeenCalled());
    const [kind, message] = toast.mock.calls[0];
    expect(kind).toBe("error");
    expect(message).toMatch(/SQL privileges cannot be saved yet/);
    expect(message).toContain("node 3: stale record");
  });

  it("passes any other refusal through unchanged", async () => {
    bridge({ put_share: () => Promise.reject(new Error("denied")) });
    const toast = vi.fn();
    const user = await openGrant(RESOURCE, toast);
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith("error", "denied"));
  });

  it("warns in the form, before the grant, while the gate is closed", async () => {
    bridge({
      policy_schema_status: () =>
        Promise.resolve({ sql_capabilities_writable: false, reason: "node 3: no version record", nodes: [] }),
    });
    await openGrant(RESOURCE);
    expect(await screen.findByTestId("sql-gate-notice")).toHaveTextContent("node 3: no version record");
  });

  it("does not ask about the gate when the grant names no SQL capability", async () => {
    const user = await openGrant({ ...RESOURCE, defaultCapabilities: ["read"] });
    await user.click(screen.getByRole("button", { name: "connect" }));
    expect(mockInvoke).not.toHaveBeenCalledWith("policy_schema_status", undefined);
    await user.click(screen.getByRole("button", { name: "sql_select" }));
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("policy_schema_status", undefined));
  });
});
