import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import type { AssetGroupInfo } from "../lib/types";

// `AssetGroupSharingCard` is the fourth wrapper over
// `ObjectSharingCard`, and the one that stretches it: its owner is a
// field on the record the parent already loaded rather than an owner
// endpoint, and it is the only surface that offers group grantees.
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

const GROUP = "fgv-prod-db";
const OWNER_ID = "11111111-1111-1111-1111-111111111111";
const GRANTEE_ID = "33333333-3333-3333-3333-333333333333";

function info(over: Partial<AssetGroupInfo> = {}): AssetGroupInfo {
  return {
    name: GROUP,
    description: "",
    members: [],
    secrets: [],
    owner_entity_id: OWNER_ID,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-01T00:00:00Z",
    ...over,
  };
}

function mockBridge(shares: unknown[] = []) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "list_shares_for_target") return Promise.resolve(shares);
    if (cmd === "list_entity_aliases") return Promise.resolve([]);
    if (cmd === "list_groups") return Promise.resolve({ groups: ["engineering"] });
    if (cmd === "put_share") return Promise.resolve({});
    if (cmd === "delete_share") return Promise.resolve(null);
    if (cmd === "transfer_asset_group_owner") return Promise.resolve(null);
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

async function renderCard(
  group: AssetGroupInfo = info(),
  onOwnerChange: () => void = () => {},
) {
  const { AssetGroupSharingCard } = await import("../routes/AssetGroupsPage");
  const view = render(
    <ToastProvider>
      <AssetGroupSharingCard info={group} onOwnerChange={onOwnerChange} />
    </ToastProvider>,
  );
  await waitFor(() =>
    expect(screen.queryByText(/loading sharing info/i)).not.toBeInTheDocument(),
  );
  return view;
}

describe("AssetGroupSharingCard owner, sourced from the parent record", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockBridge();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: OWNER_ID,
    });
  });

  it("renders the owner off AssetGroupInfo without an owner lookup", async () => {
    await renderCard();
    expect(screen.getByText(OWNER_ID)).toBeInTheDocument();
    expect(screen.getByText("You")).toBeInTheDocument();
    // There is no `sys/asset-group-owner/read` — a second source here
    // could disagree with the detail header.
    const commands = mockInvoke.mock.calls.map((c) => c[0]);
    expect(commands.filter((c) => String(c).endsWith("_owner"))).toEqual([]);
  });

  it("lists shares against the asset-group kind, keyed by group name", async () => {
    await renderCard();
    expect(mockInvoke).toHaveBeenCalledWith("list_shares_for_target", {
      kind: "asset-group",
      targetPath: GROUP,
    });
  });

  it("explains that an unowned group is never captured by a later write", async () => {
    await renderCard(info({ owner_entity_id: "" }));
    expect(
      screen.getByText(/An admin can claim it or assign an owner/i),
    ).toBeInTheDocument();
    // The generic copy the other kinds get would be wrong here: asset
    // group ownership is taken on create and never again.
    expect(
      screen.queryByText(/next authenticated write/i),
    ).not.toBeInTheDocument();
  });

  it("transfers through the asset-group endpoint and asks the parent to refetch", async () => {
    const onOwnerChange = vi.fn();
    const user = userEvent.setup();
    await renderCard(info(), onOwnerChange);
    await user.click(screen.getByRole("button", { name: /^transfer$/i }));
    await user.type(
      screen.getByPlaceholderText(/target entity uuid/i),
      GRANTEE_ID,
    );
    await user.click(
      screen.getAllByRole("button", { name: /^transfer$/i }).slice(-1)[0],
    );
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("transfer_asset_group_owner", {
        name: GROUP,
        newOwnerEntityId: GRANTEE_ID,
      }),
    );
    // The card cannot refresh a value it does not own.
    await waitFor(() => expect(onOwnerChange).toHaveBeenCalled());
  });

  it("keeps the ownership controls on a literal root/admin policy", async () => {
    useAuthStore.setState({ policies: ["super-admin"], entityId: "someone" });
    await renderCard();
    expect(
      screen.queryByRole("button", { name: /^transfer$/i }),
    ).not.toBeInTheDocument();
  });
});

describe("AssetGroupSharingCard group grantees", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockBridge();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: OWNER_ID,
    });
  });

  it("grants to a user identity group with the group kind", async () => {
    const user = userEvent.setup();
    await renderCard();
    await user.click(screen.getByRole("button", { name: /grant access/i }));
    await user.selectOptions(
      screen.getByLabelText(/grantee kind/i),
      "group_user",
    );
    await user.type(
      screen.getByPlaceholderText("engineering"),
      "engineering",
    );
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("put_share", {
        kind: "asset-group",
        targetPath: GROUP,
        grantee: "engineering",
        granteeKind: "group_user",
        capabilities: ["read"],
        expiresAt: "",
      }),
    );
  });

  it("still defaults to an entity grantee", async () => {
    const user = userEvent.setup();
    await renderCard();
    await user.click(screen.getByRole("button", { name: /grant access/i }));
    await user.type(
      screen.getByPlaceholderText(/paste entity_id/i),
      GRANTEE_ID,
    );
    await user.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("put_share", {
        kind: "asset-group",
        targetPath: GROUP,
        grantee: GRANTEE_ID,
        granteeKind: "entity",
        capabilities: ["read"],
        expiresAt: "",
      }),
    );
  });

  it("revokes an app-group share with its own kind", async () => {
    mockInvoke.mockReset();
    mockBridge([
      {
        target_kind: "asset-group",
        target_path: GROUP,
        grantee_kind: "group_app",
        grantee_entity_id: "ci-bots",
        granted_by_entity_id: OWNER_ID,
        capabilities: ["read", "connect"],
        granted_at: "2026-09-01T10:00:00Z",
        expires_at: "",
        expired: false,
      },
    ]);
    const user = userEvent.setup();
    await renderCard();
    expect(screen.getByText("app group")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /revoke/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("delete_share", {
        kind: "asset-group",
        targetPath: GROUP,
        grantee: "ci-bots",
        granteeKind: "group_app",
      }),
    );
  });
});
