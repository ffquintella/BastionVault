import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// Tauri bridge stub — the sharing card reads the owner record and the
// share list on mount and writes through `transfer_resource_owner`.
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

const noopToast = () => {};

function mountUnowned() {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "get_resource_owner") return Promise.resolve({ owned: false });
    if (cmd === "list_shares_for_target") return Promise.resolve([]);
    if (cmd === "transfer_resource_owner") return Promise.resolve(null);
    if (cmd === "list_entity_aliases") return Promise.resolve([]);
    return Promise.reject(new Error(`unmocked: ${cmd}`));
  });
}

async function renderCard(props: Record<string, unknown> = {}) {
  const { ResourceSharingCard } = await import("../routes/ResourcesPage");
  const view = render(
    <ToastProvider>
      <ResourceSharingCard
        resourceName="segdc1vds0005"
        toast={noopToast}
        {...props}
      />
    </ToastProvider>,
  );
  await waitFor(() =>
    expect(screen.queryByText(/loading sharing info/i)).not.toBeInTheDocument(),
  );
  return view;
}

describe("ResourceSharingCard ownership controls", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mountUnowned();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  it("offers Claim ownership on an unowned resource when the caller is an admin", async () => {
    await renderCard();
    expect(
      screen.getByRole("button", { name: /claim ownership/i }),
    ).toBeInTheDocument();
  });

  it("claims by stamping the caller's own entity_id as the owner", async () => {
    const user = userEvent.setup();
    await renderCard();
    await user.click(screen.getByRole("button", { name: /claim ownership/i }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("transfer_resource_owner", {
        resource: "segdc1vds0005",
        newOwnerEntityId: "entity-1",
      }),
    );
  });

  it("recognizes a delegated admin policy, not just root/admin", async () => {
    useAuthStore.setState({ policies: ["super-admin"], entityId: "entity-1" });
    await renderCard();
    expect(
      screen.getByRole("button", { name: /claim ownership/i }),
    ).toBeInTheDocument();
  });

  it("hides the ownership controls from a non-admin caller", async () => {
    useAuthStore.setState({ policies: ["default"], entityId: "entity-1" });
    await renderCard();
    expect(
      screen.queryByRole("button", { name: /claim ownership/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /assign owner/i }),
    ).not.toBeInTheDocument();
  });

  it("labels the transfer control 'Assign owner' while unowned", async () => {
    await renderCard();
    expect(
      screen.getByRole("button", { name: /assign owner/i }),
    ).toBeInTheDocument();
  });

  it("says Transfer once the resource has an owner", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_resource_owner")
        return Promise.resolve({ owned: true, entity_id: "entity-9" });
      if (cmd === "list_shares_for_target") return Promise.resolve([]);
      if (cmd === "list_entity_aliases") return Promise.resolve([]);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    await renderCard();
    expect(screen.getByRole("button", { name: /^transfer$/i })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /claim ownership/i }),
    ).not.toBeInTheDocument();
  });
});

describe("ResourceSharingCard share request from the detail header", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mountUnowned();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  it("opens the Grant modal when the header asks to share", async () => {
    const onGrantHandled = vi.fn();
    await renderCard({ openGrant: true, onGrantHandled });
    await waitFor(() =>
      expect(screen.getByText(/grant access to segdc1vds0005/i)).toBeInTheDocument(),
    );
    // The request is consumed once so re-entering the tab doesn't reopen it.
    expect(onGrantHandled).toHaveBeenCalled();
  });

  it("does not open the Grant modal for a caller who cannot share", async () => {
    useAuthStore.setState({ policies: ["default"], entityId: "entity-1" });
    const onGrantHandled = vi.fn();
    await renderCard({ openGrant: true, onGrantHandled });
    await waitFor(() => expect(onGrantHandled).toHaveBeenCalled());
    expect(
      screen.queryByText(/grant access to segdc1vds0005/i),
    ).not.toBeInTheDocument();
  });
});
