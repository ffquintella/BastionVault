import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// Tauri bridge stub. The list view reads the type config, the search
// page and the batched capabilities probe on mount; the Connect click
// then reads the resource and opens the session.
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

const RESOURCE = "evdc400";

/** The exact shape behind the screenshot that prompted this test: one
 *  RDP profile, flagged default, credential source `default-account`. */
const PROFILE = {
  id: "cp_1",
  name: "Default",
  protocol: "rdp",
  host: "evdc400.fgv.br",
  port: 3389,
  is_default: true,
  credential_source: { kind: "default-account" },
};

function mockVault({ hasWindowsPassword }: { hasWindowsPassword: boolean }) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "resource_types_read":
        return Promise.resolve(null);
      case "list_asset_groups":
        return Promise.resolve({ groups: [] });
      case "asset_groups_for_resource":
        return Promise.resolve({ groups: [] });
      case "search_resources":
        return Promise.resolve({
          items: [
            {
              name: RESOURCE,
              type: "server",
              hostname: "evdc400.fgv.br",
              connect_profiles: [
                { protocol: "rdp", credential_source: { kind: "default-account" } },
              ],
            },
          ],
          total: 1,
          has_more: false,
        });
      case "read_resource":
        return Promise.resolve({
          name: RESOURCE,
          type: "server",
          os_type: "windows",
          hostname: "evdc400.fgv.br",
          connection_profiles: [PROFILE],
        });
      // Caller can read the resource's secrets — not a connect-only one.
      case "capabilities_self":
        return Promise.resolve({ paths: { [`resources/secrets/${RESOURCE}/`]: ["read"] } });
      case "get_default_account_self":
        return Promise.resolve({
          linux: "",
          macos: "",
          windows: "FGV\\felipe",
          has_windows_password: hasWindowsPassword,
        });
      case "connect_mfa_begin":
        return Promise.resolve({ required: false });
      case "session_open_rdp":
        return Promise.resolve({ session_id: "s1" });
      default:
        return Promise.reject(new Error(`unmocked: ${cmd}`));
    }
  });
}

async function renderResources() {
  const { ResourcesPage } = await import("../routes/ResourcesPage");
  render(
    <MemoryRouter>
      <ToastProvider>
        <ResourcesPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await screen.findByText(RESOURCE);
}

function connectChip() {
  // The card's chip, not the detail view's button: role="button" span.
  return screen.getAllByTitle("Connect")[0];
}

describe("resource card quick-Connect", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      policies: ["admin"],
      entityId: "entity-1",
    });
  });

  it("opens the session directly when the default profile needs nothing typed", async () => {
    mockVault({ hasWindowsPassword: true });
    await renderResources();

    await userEvent.click(connectChip());

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("session_open_rdp", {
        request: expect.objectContaining({
          resource_name: RESOURCE,
          profile_id: PROFILE.id,
        }),
      }),
    );
    // Regression: this used to route to the detail view's Connection tab
    // instead of dialling, even though the tab would have launched
    // without asking anything.
    expect(screen.queryByText("Connection profiles")).not.toBeInTheDocument();
  });

  it("prompts inline — not via the detail view — when the account has no stored password", async () => {
    mockVault({ hasWindowsPassword: false });
    await renderResources();

    await userEvent.click(connectChip());

    // The card's own credential modal, one level deep.
    await screen.findByText(`Account password · ${PROFILE.name}`);
    expect(screen.queryByText("Connection profiles")).not.toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalledWith("session_open_rdp", expect.anything());

    await userEvent.type(screen.getByLabelText("Password"), "hunter2");
    // The modal's submit is a real <button>; the card chip behind it is a
    // <span role="button">, so both answer this role query.
    const submit = screen
      .getAllByRole("button", { name: "Connect" })
      .find((el) => el.tagName === "BUTTON")!;
    await userEvent.click(submit);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("session_open_rdp", {
        request: expect.objectContaining({
          resource_name: RESOURCE,
          profile_id: PROFILE.id,
          operator_credential: { username: "", password: "hunter2" },
        }),
      }),
    );
  });
});
