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

  it("renders config and credentials sections", async () => {
    mockInvoke.mockResolvedValueOnce({ rp_id: "localhost", rp_origin: "https://localhost", rp_name: "Test" });
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("Relying Party Configuration")).toBeInTheDocument();
      expect(screen.getByText("Manage Credentials")).toBeInTheDocument();
    });
  });

  it("shows not configured when no config exists", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("Not configured")).toBeInTheDocument();
    });
  });

  it("shows configure button when no config", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const { Fido2Page } = await import("../routes/Fido2Page");
    renderWithProviders(<Fido2Page />);

    await waitFor(() => {
      expect(screen.getByText("Configure")).toBeInTheDocument();
    });
  });
});
