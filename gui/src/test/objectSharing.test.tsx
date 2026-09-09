import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// `ObjectSharingCard` is the single implementation behind the three
// per-kind wrappers. These tests cover what the wrappers actually
// parameterize — the owner/claim adapters and the admin gate — since
// the shared body is already exercised by resourceSharing.test.tsx and
// fileSharing.test.tsx.
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

const KV_PATH = "secret/team/db";

function mountUnowned() {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "get_kv_owner") return Promise.resolve({ owned: false });
    if (cmd === "list_shares_for_target") return Promise.resolve([]);
    if (cmd === "claim_kv_owner") return Promise.resolve(null);
    if (cmd === "put_share") return Promise.resolve({});
    if (cmd === "list_entity_aliases") return Promise.resolve([]);
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

async function renderPanel() {
  const { SecretSharingPanel } = await import("../routes/SecretsPage");
  const view = render(
    <ToastProvider>
      <SecretSharingPanel fullPath={KV_PATH} displayPath={`ns/${KV_PATH}`} />
    </ToastProvider>,
  );
  await waitFor(() =>
    expect(screen.queryByText(/loading sharing info/i)).not.toBeInTheDocument(),
  );
  return view;
}

describe("SecretSharingPanel ownership controls", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mountUnowned();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["default"],
      entityId: "entity-1",
    });
  });

  it("looks up the owner and shares against the KV kind, keyed by the canonical path", async () => {
    await renderPanel();
    expect(mockInvoke).toHaveBeenCalledWith("get_kv_owner", { path: KV_PATH });
    expect(mockInvoke).toHaveBeenCalledWith("list_shares_for_target", {
      kind: "kv-secret",
      targetPath: KV_PATH,
    });
  });

  it("offers Claim ownership to a non-admin caller, because KV has a real claim endpoint", async () => {
    const user = userEvent.setup();
    await renderPanel();
    await user.click(screen.getByRole("button", { name: /claim ownership/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("claim_kv_owner", {
        path: KV_PATH,
      }),
    );
    // Never via the admin transfer endpoint, unlike resources and files.
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "transfer_kv_owner",
      expect.anything(),
    );
  });

  it("keeps the transfer control admin-only", async () => {
    await renderPanel();
    expect(
      screen.queryByRole("button", { name: /assign owner/i }),
    ).not.toBeInTheDocument();
  });

  it("gates the transfer control on a literal root/admin policy, not the delegated set", async () => {
    // Deliberate divergence from resources and files, which accept the
    // wider `isAdminUser` set. GUI gating only; preserved as-is by the
    // extraction so any widening is a decision of its own.
    useAuthStore.setState({ policies: ["super-admin"], entityId: "entity-1" });
    await renderPanel();
    expect(
      screen.queryByRole("button", { name: /assign owner/i }),
    ).not.toBeInTheDocument();

    useAuthStore.setState({ policies: ["admin"], entityId: "entity-1" });
    await renderPanel();
    expect(
      screen.getAllByRole("button", { name: /assign owner/i }).length,
    ).toBeGreaterThan(0);
  });

  it("does not offer connect, which is resource-only", async () => {
    useAuthStore.setState({ policies: ["admin"], entityId: "entity-1" });
    const user = userEvent.setup();
    await renderPanel();
    await user.click(screen.getByRole("button", { name: /grant access/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "read" })).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "connect" }),
    ).not.toBeInTheDocument();
  });

  it("grants on the canonical path, not the namespaced display path", async () => {
    useAuthStore.setState({ policies: ["admin"], entityId: "entity-1" });
    const user = userEvent.setup();
    await renderPanel();
    await user.click(screen.getByRole("button", { name: /grant access/i }));
    // EntityPicker only propagates free text that parses as a UUID.
    await user.type(
      screen.getByPlaceholderText(/paste entity_id/i),
      "33333333-3333-3333-3333-333333333333",
    );
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("put_share", {
        kind: "kv-secret",
        targetPath: KV_PATH,
        grantee: "33333333-3333-3333-3333-333333333333",
        granteeKind: "entity",
        capabilities: ["read"],
        expiresAt: "",
      }),
    );
  });
});

// Group grantees are only *offered* on asset groups, but a group share
// can land on any kind through the API or the CLI. Before this, revoke
// sent a hardcoded `entity` kind and silently mis-targeted the record —
// the row stayed after a "Share revoked" toast.
describe("ObjectSharingCard revoke honours the record's grantee_kind", () => {
  const GROUP_SHARE = {
    target_kind: "kv-secret",
    target_path: KV_PATH,
    grantee_kind: "group_user" as const,
    grantee_entity_id: "engineering",
    granted_by_entity_id: "entity-1",
    capabilities: ["read"],
    granted_at: "2026-09-01T10:00:00Z",
    expires_at: "",
    expired: false,
  };

  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_kv_owner")
        return Promise.resolve({ owned: true, entity_id: "entity-1" });
      if (cmd === "list_shares_for_target")
        return Promise.resolve([GROUP_SHARE]);
      if (cmd === "delete_share") return Promise.resolve(null);
      if (cmd === "list_entity_aliases") return Promise.resolve([]);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  it("sends group_user, not the entity default, when revoking a group share", async () => {
    const user = userEvent.setup();
    await renderPanel();
    await user.click(screen.getByRole("button", { name: /revoke/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("delete_share", {
        kind: "kv-secret",
        targetPath: KV_PATH,
        grantee: "engineering",
        granteeKind: "group_user",
      }),
    );
  });

  it("labels a group grantee as a group instead of resolving it as an entity", async () => {
    await renderPanel();
    expect(screen.getByText("user group")).toBeInTheDocument();
    expect(screen.getByText("engineering")).toBeInTheDocument();
  });
});
