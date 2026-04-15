import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// Mock the Tauri invoke API at the module level
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function renderWithProviders(ui: React.ReactNode, { route = "/" } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false });
  });

  it("renders token and userpass tabs", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    // "Token" appears as both a tab label and an input label
    expect(screen.getAllByText("Token").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("UserPass")).toBeInTheDocument();
  });

  it("renders token input field on token tab", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    expect(screen.getByPlaceholderText("hvs.xxxxx...")).toBeInTheDocument();
  });

  it("disables sign in button when token is empty", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    const buttons = screen.getAllByRole("button", { name: /sign in/i });
    expect(buttons[0]).toBeDisabled();
  });

  it("calls login_token on form submit", async () => {
    mockInvoke.mockResolvedValueOnce({ token: "hvs.test", policies: ["root"] });
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    const input = screen.getByPlaceholderText("hvs.xxxxx...");
    await user.type(input, "hvs.test-token");

    const button = screen.getAllByRole("button", { name: /sign in/i })[0];
    await user.click(button);

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("login_token", { token: "hvs.test-token" });
    });
  });

  it("switches to userpass tab and shows username/password fields", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getByText("UserPass"));
    expect(screen.getByText("Username")).toBeInTheDocument();
    expect(screen.getByText("Password")).toBeInTheDocument();
  });
});

describe("InitPage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false });
  });

  it("renders initialize button", async () => {
    const { InitPage } = await import("../routes/InitPage");
    renderWithProviders(<InitPage />);
    expect(screen.getByRole("button", { name: /initialize vault/i })).toBeInTheDocument();
  });

  it("shows root token after initialization", async () => {
    mockInvoke.mockResolvedValueOnce({ root_token: "hvs.root-token-123" });
    const user = userEvent.setup();
    const { InitPage } = await import("../routes/InitPage");
    renderWithProviders(<InitPage />);

    await user.click(screen.getByRole("button", { name: /initialize vault/i }));

    await waitFor(() => {
      expect(screen.getByDisplayValue("hvs.root-token-123")).toBeInTheDocument();
    });
  });
});

describe("ConnectPage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("shows local vault option", async () => {
    mockInvoke.mockResolvedValueOnce(false); // is_vault_initialized
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => {
      expect(screen.getByText("Local Vault")).toBeInTheDocument();
    });
  });

  it("shows remote option as enabled", async () => {
    mockInvoke.mockResolvedValueOnce(false);
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => {
      expect(screen.getByText("Connect to Server")).toBeInTheDocument();
    });
    const remoteBtn = screen.getByText("Connect to Server").closest("button");
    expect(remoteBtn).not.toBeDisabled();
  });
});
