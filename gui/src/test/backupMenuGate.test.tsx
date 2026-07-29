/**
 * The File → Backup menu is root-only.
 *
 * Full-vault export/restore go through Tauri commands that refuse any
 * token whose policies lack the literal `root`
 * (`commands/backup.rs::require_root`), and no auth backend can mint a
 * root token — the token store rejects it outright ("auth methods
 * cannot create root tokens"). So for a userpass / AppRole / FIDO2
 * session the menu items could only ever fail, and only *after* the
 * operator typed a 16-character password twice. `Layout` therefore
 * withholds the handlers, which makes `AppMenu` drop the submenu.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { Layout } from "../components/Layout";
import { useAuthStore } from "../stores/authStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

// Layout mounts background fetches (plugin surfaces, notifications,
// namespaces) and child components that reach for the vault over IPC.
// None of them are under test here — override just the ones Layout's
// mount path touches and leave the rest of the module intact so any
// call we didn't anticipate still resolves through `mockInvoke`.
vi.mock("../lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/api")>()),
  listPluginSurfaces: () => Promise.resolve({ surfaces: [] }),
  listNotifications: () => Promise.resolve({ notifications: [] }),
  namespacesSelf: () =>
    Promise.resolve({ namespaces: [], token_namespace: "", root: false }),
  getActiveNamespace: () => Promise.resolve({ namespace: "" }),
  logout: () => Promise.resolve(),
}));

/** Sign in with `policies` and open the hamburger menu. */
async function openMenu(policies: string[]) {
  useAuthStore.setState({
    token: "test-token",
    policies,
    isAuthenticated: true,
  });
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <ToastProvider>
        <Layout>
          <div>page body</div>
        </Layout>
      </ToastProvider>
    </MemoryRouter>,
  );
  await user.click(screen.getByRole("button", { name: /menu/i }));
  return user;
}

describe("File → Backup menu gating", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
    useAuthStore.setState({ token: "", policies: [], isAuthenticated: false });
  });

  it("hides Backup from a session without the root policy", async () => {
    await openMenu(["administrator", "default"]);
    // The submenu parent is gone, so neither leaf is reachable.
    expect(screen.queryByText("Backup")).not.toBeInTheDocument();
    expect(screen.queryByText("Export…")).not.toBeInTheDocument();
    expect(screen.queryByText("Restore…")).not.toBeInTheDocument();
    // The rest of the menu still renders — this hides one entry, not the menu.
    expect(screen.getByText("About BastionVault")).toBeInTheDocument();
  });

  it("shows Export and Restore to a root-token session", async () => {
    const user = await openMenu(["root"]);
    // The submenu opens on hover; a click would open it on the
    // synthetic pointerover and immediately toggle it back shut.
    await user.hover(screen.getByText("Backup"));
    expect(screen.getByText("Export…")).toBeInTheDocument();
    expect(screen.getByText("Restore…")).toBeInTheDocument();
  });

  it("opens the export modal for root", async () => {
    const user = await openMenu(["root"]);
    await user.hover(screen.getByText("Backup"));
    await user.click(screen.getByText("Export…"));
    expect(await screen.findByText("Export full backup")).toBeInTheDocument();
  });
});
