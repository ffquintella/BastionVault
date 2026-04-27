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
    // SettingsPage is now organised into tabs (general / security /
    // identity / …) and persists the active tab in localStorage. The
    // FIDO2 card moved to the `"security"` tab; without this preset
    // the page renders the General tab and these tests can't see
    // any FIDO2 markup. Setting the storage value before mount picks
    // up the right tab via the page's lazy-init `useState` hook.
    try {
      localStorage.setItem("settings.activeTab", "security");
    } catch {
      /* jsdom occasionally fails on storage; tests fall back to
         general tab and would FAIL — that's the right signal. */
    }
  });

  function mockSettingsInvoke(fido2Config: unknown) {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "fido2_config_read") return Promise.resolve(fido2Config);
      if (cmd === "fido2_config_write") return Promise.resolve();
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
  }

  it("shows FIDO2 config in settings", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("FIDO2 / Security Keys")).toBeInTheDocument();
      expect(screen.getByText("localhost")).toBeInTheDocument();
    });
  });

  it("shows edit button for FIDO2 config", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      // There may be multiple "Edit" buttons; at least one should exist for FIDO2
      expect(screen.getAllByText("Edit").length).toBeGreaterThanOrEqual(1);
    });
  });

  it("switches to edit mode when Edit is clicked", async () => {
    mockSettingsInvoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const user = userEvent.setup();
    const { SettingsPage } = await import("../routes/SettingsPage");
    renderWithProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText("localhost")).toBeInTheDocument();
    });

    // Click the Edit button (first one is the FIDO2 card)
    await user.click(screen.getAllByText("Edit")[0]);

    expect(screen.getByDisplayValue("localhost")).toBeInTheDocument();
    expect(screen.getByText("Save")).toBeInTheDocument();
  });
});
