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

  it("renders Login and Token tabs", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    expect(screen.getByText("Login")).toBeInTheDocument();
    // "Token" appears as both a tab label and an input label on the token tab
    expect(screen.getAllByText("Token").length).toBeGreaterThanOrEqual(1);
  });

  it("shows username field on the default Login tab", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    // Login tab is default, shows username field
    expect(screen.getByPlaceholderText("alice")).toBeInTheDocument();
    expect(screen.getByText("Continue")).toBeInTheDocument();
  });

  it("renders token input field on Token tab", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getAllByText("Token")[0]);
    expect(screen.getByPlaceholderText("hvs.xxxxx...")).toBeInTheDocument();
  });

  it("disables sign in button when token is empty", async () => {
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getAllByText("Token")[0]);
    const buttons = screen.getAllByRole("button", { name: /sign in/i });
    expect(buttons[0]).toBeDisabled();
  });

  it("calls login_token on form submit", async () => {
    mockInvoke.mockResolvedValueOnce({ token: "hvs.test", policies: ["root"] });
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getAllByText("Token")[0]);
    const input = screen.getByPlaceholderText("hvs.xxxxx...");
    await user.type(input, "hvs.test-token");

    const button = screen.getAllByRole("button", { name: /sign in/i })[0];
    await user.click(button);

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("login_token", { token: "hvs.test-token" });
    });
  });

  it("disables Continue button when username is empty", async () => {
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);
    const btn = screen.getByText("Continue").closest("button");
    expect(btn).toBeDisabled();
  });
});

describe("InitPage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false });
  });

  it("renders initialize button", async () => {
    // Mock is_vault_initialized returning false so it shows the init form
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "is_vault_initialized") return Promise.resolve(false);
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const { InitPage } = await import("../routes/InitPage");
    renderWithProviders(<InitPage />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /initialize vault/i })).toBeInTheDocument();
    });
  });

  it("shows root token after initialization", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "is_vault_initialized") return Promise.resolve(false);
      if (cmd === "init_vault") return Promise.resolve({ root_token: "hvs.root-token-123" });
      if (cmd === "save_preferences") return Promise.resolve();
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const user = userEvent.setup();
    const { InitPage } = await import("../routes/InitPage");
    renderWithProviders(<InitPage />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /initialize vault/i })).toBeInTheDocument();
    });

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

  it("renders the add-new chooser when no profiles are saved", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_vault_profiles")
        return Promise.resolve({ vaults: [], lastUsedId: null });
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => {
      expect(screen.getByText(/Add new vault/i)).toBeInTheDocument();
    });
    // All three kinds of add-new action are offered.
    expect(screen.getByText("Local")).toBeInTheDocument();
    expect(screen.getByText("Server")).toBeInTheDocument();
    expect(screen.getByText("Cloud")).toBeInTheDocument();
  });

  it("lists saved vault profiles", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_vault_profiles")
        return Promise.resolve({
          vaults: [
            {
              id: "v1",
              name: "Home lab",
              spec: { kind: "local", storage_kind: "file" },
            },
            {
              id: "v2",
              name: "Prod",
              spec: {
                kind: "remote",
                profile: {
                  name: "Prod",
                  address: "https://vault.example.com:8200",
                  tls_skip_verify: false,
                },
              },
            },
          ],
          lastUsedId: "v2",
        });
      // Block auto-resume so we render the chooser rather than
      // navigating off the page.
      if (cmd === "connect_remote")
        return Promise.reject(new Error("no network in test"));
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => {
      expect(screen.getByText("Home lab")).toBeInTheDocument();
    });
    expect(screen.getByText("Prod")).toBeInTheDocument();
  });
});
