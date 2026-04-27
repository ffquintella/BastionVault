import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function renderWithProviders(ui: React.ReactNode) {
  return render(
    <MemoryRouter>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  );
}

describe("SettingsPage FIDO2 config", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "test-token", policies: ["root"], isAuthenticated: true });
    // SettingsPage persists the active tab in localStorage and reads
    // it through a lazy `useState` initialiser. We don't rely on
    // priming localStorage here — `gotoSecurityTab()` clicks the
    // tab button after mount, which is both more reliable across
    // jsdom resets and a more honest user-flow assertion.
    try {
      localStorage.removeItem("settings.activeTab");
    } catch {
      /* jsdom storage absent — tests still drive the tab via clicks. */
    }
  });

  function mockSettingsInvoke(fido2Config: unknown) {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "fido2_config_read") return Promise.resolve(fido2Config);
      if (cmd === "fido2_config_write") return Promise.resolve();
      // Other commands the page fires on mount (vault profiles, mounts,
      // SSO admin list, YubiKey state, password policy, resource types,
      // …) are not relevant to these tests; resolve cheaply with a
      // best-effort empty payload so the page mounts cleanly.
      if (cmd === "list_mounts") return Promise.resolve([]);
      if (cmd === "list_vault_profiles") return Promise.resolve({ vaults: [], lastUsedId: null });
      if (cmd === "yubikey_list_registered") return Promise.resolve([]);
      if (cmd === "yubikey_list_devices") return Promise.resolve([]);
      if (cmd === "get_sso_settings") return Promise.resolve(false);
      if (cmd === "sso_admin_list") return Promise.resolve([]);
      if (cmd === "resource_types_read") return Promise.resolve(null);
      if (cmd === "get_password_policy")
        return Promise.resolve({ min_length: 12, require_upper: true, require_lower: true, require_digit: true, require_symbol: false });
      // Unknown commands resolve with `null` rather than reject — the
      // page's many independent loaders all swallow rejections, but a
      // resolved-null leaves the corresponding state at its default
      // and avoids flooding the test log with caught-but-noisy errors.
      return Promise.resolve(null);
    });
  }

  /// The FIDO2 card lives on the Security tab. SettingsPage opens to
  /// General by default; click the Security tab button so the FIDO2
  /// card is in the rendered tree.
  async function gotoSecurityTab(user: ReturnType<typeof userEvent.setup>) {
    const tab = await screen.findByRole("button", { name: "Security" });
    await user.click(tab);
  }

  it("shows FIDO2 config in settings", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const user = userEvent.setup();
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await gotoSecurityTab(user);

    expect(await screen.findByText("FIDO2 / Security Keys")).toBeInTheDocument();
    expect(await screen.findByText("localhost")).toBeInTheDocument();
  });

  it("shows edit button for FIDO2 config", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const user = userEvent.setup();
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await gotoSecurityTab(user);

    // There may be multiple "Edit" buttons across the Security tab
    // (FIDO2, Password Policy, …); at least one is the FIDO2 card's.
    const edits = await screen.findAllByText("Edit");
    expect(edits.length).toBeGreaterThanOrEqual(1);
  });

  it("switches to edit mode when Edit is clicked", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const user = userEvent.setup();
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await gotoSecurityTab(user);

    await screen.findByText("localhost");

    // Click the FIDO2 card's Edit button. The card is the first one
    // on the Security tab, so its Edit is `getAllByText("Edit")[0]`.
    await user.click(screen.getAllByText("Edit")[0]);

    expect(await screen.findByDisplayValue("localhost")).toBeInTheDocument();
    expect(screen.getByText("Save")).toBeInTheDocument();
  });
});
