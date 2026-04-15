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

describe("LoginPage FIDO2 tab", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false });
  });

  it("renders FIDO2 tab", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    expect(screen.getByText("FIDO2")).toBeInTheDocument();
  });

  it("shows security key button when FIDO2 tab is selected", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getByText("FIDO2"));
    expect(screen.getByText("Authenticate with Security Key")).toBeInTheDocument();
  });

  it("shows username field in FIDO2 tab", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getByText("FIDO2"));
    expect(screen.getByPlaceholderText("alice")).toBeInTheDocument();
  });

  it("disables authenticate button when username is empty", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getByText("FIDO2"));
    const btn = screen.getByText("Authenticate with Security Key").closest("button");
    expect(btn).toBeDisabled();
  });
});

describe("Fido2Page", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "test-token", policies: ["root"], isAuthenticated: true });
  });

  function mockFido2Invoke(config: unknown) {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_auth_methods") return Promise.resolve([{ path: "fido2/", mount_type: "fido2", description: "" }]);
      if (cmd === "fido2_config_read") return Promise.resolve(config);
      if (cmd === "fido2_config_write") return Promise.resolve();
      if (cmd === "enable_auth_method") return Promise.resolve();
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
  }

  it("renders config and credentials sections", async () => {
    mockFido2Invoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("Relying Party Configuration")).toBeInTheDocument();
      expect(screen.getByText("Manage Credentials")).toBeInTheDocument();
    });
  });

  it("shows config values when config exists", async () => {
    mockFido2Invoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("localhost")).toBeInTheDocument();
    });
  });

  it("shows edit button for config", async () => {
    mockFido2Invoke({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("Edit")).toBeInTheDocument();
    });
  });
});
