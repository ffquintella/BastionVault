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

describe("ResourceSharingCard connect capability", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mountUnowned();
    // `mountUnowned` rejects anything it doesn't know; the grant path needs
    // `put_share` to resolve.
    const unowned = mockInvoke.getMockImplementation()!;
    mockInvoke.mockImplementation((cmd: string, ...rest: unknown[]) =>
      cmd === "put_share"
        ? Promise.resolve({})
        : unowned(cmd, ...rest),
    );
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  it("offers connect as a grantable capability", async () => {
    await renderCard({ openGrant: true, onGrantHandled: vi.fn() });
    await waitFor(() =>
      expect(
        screen.getByText(/grant access to segdc1vds0005/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "connect" })).toBeInTheDocument();
  });

  it("grants connect on its own, without read", async () => {
    const user = userEvent.setup();
    await renderCard({ openGrant: true, onGrantHandled: vi.fn() });
    await waitFor(() =>
      expect(
        screen.getByText(/grant access to segdc1vds0005/i),
      ).toBeInTheDocument(),
    );

    // `read` is the default selection; drop it so the share is connect-only —
    // the grantee dials the target but never sees the credential.
    await user.click(screen.getByRole("button", { name: "read" }));
    await user.click(screen.getByRole("button", { name: "connect" }));

    // EntityPicker's label is not bound to the input, so target the field by
    // its placeholder. It only propagates a typed value when it looks like a
    // full entity UUID — anything shorter waits for a dropdown selection.
    const grantee = screen.getByPlaceholderText(/paste entity_id/i);
    await user.type(grantee, "62859f4d-0925-4933-4890-0f84e55693bd");
    await user.click(screen.getByRole("button", { name: /^grant$/i }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith(
        "put_share",
        expect.objectContaining({ capabilities: ["connect"] }),
      ),
    );
  });

  it("says connect is not implied by read", async () => {
    await renderCard({ openGrant: true, onGrantHandled: vi.fn() });
    await waitFor(() =>
      expect(
        screen.getByText(/grant access to segdc1vds0005/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/is not implied by/i)).toBeInTheDocument();
  });
});
