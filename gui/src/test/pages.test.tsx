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

// LoginPage mounts with `listen()` calls against the Tauri event bus
// (FIDO2 status + PIN prompt channels). Without this mock, each
// `listen()` tries to use the real `window.__TAURI_INTERNALS__` which
// isn't present under jsdom — producing the `transformCallback`
// unhandled rejections we were seeing as "Vitest caught N unhandled
// errors during the test run". Returning a no-op unlisten keeps the
// page's useEffect cleanup path happy.
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

// Similarly, the Reset-vault button shells out via `@tauri-apps/plugin-shell`
// `open()`. Not relied on by any assertion but the LoginPage imports
// it at the top level; stub it so import resolution works under jsdom.
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
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
    // The page mounts with a background `list_sso_providers` fetch
    // (unauth discovery for the SSO tab). Tests that don't care
    // about SSO still need the call to resolve, not return undefined.
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_sso_providers") {
        return Promise.resolve({ enabled: false, providers: [] });
      }
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
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

  it("offers an unseal action when login fails because the vault is sealed", async () => {
    // A sealed barrier blocks token auth; the backend reports it as a
    // "sealed" error. The login page must turn that dead-end into an
    // unseal entry point rather than just a red message.
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_sso_providers")
        return Promise.resolve({ enabled: false, providers: [] });
      if (cmd === "login_token")
        return Promise.reject({
          message:
            "node `https://vault.example.com:4200` is unavailable: BastionVault is sealed.",
        });
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const user = userEvent.setup();
    const { LoginPage } = await import("../routes/LoginPage");
    renderWithProviders(<LoginPage />);

    await user.click(screen.getAllByText("Token")[0]);
    await user.type(screen.getByPlaceholderText("hvs.xxxxx..."), "hvs.test");
    await user.click(screen.getAllByRole("button", { name: /sign in/i })[0]);

    // The sealed error surfaces an "Unseal vault" button that opens the
    // unseal dialog without leaving the login page.
    const unsealBtn = await screen.findByRole("button", {
      name: /unseal vault/i,
    });
    await user.click(unsealBtn);
    expect(
      screen.getByRole("heading", { name: /unseal vault/i }),
    ).toBeInTheDocument();
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

  it("offers an unseal action when a remote connect fails because the cluster is sealed", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_vault_profiles")
        return Promise.resolve({
          vaults: [
            {
              id: "v1",
              name: "HML - Cluster",
              spec: {
                kind: "remote",
                profile: {
                  name: "HML - Cluster",
                  address: "esi.fgv.br",
                  tls_skip_verify: false,
                },
              },
            },
          ],
          lastUsedId: null,
        });
      // Every node sealed → discovery finds no healthy node and connect
      // fails outright, before any profile is stored in AppState.
      if (cmd === "connect_remote")
        return Promise.reject({
          message:
            "Cluster discovery failed: no healthy node found for `esi.fgv.br`: n4=Sealed, n3=Sealed",
        });
      return Promise.reject(new Error(`unmocked: ${cmd}`));
    });
    const user = userEvent.setup();
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() =>
      expect(screen.getByText("HML - Cluster")).toBeInTheDocument(),
    );
    await user.click(screen.getByText("HML - Cluster"));

    // The sealed connect error surfaces an inline "Unseal vault" button.
    const unsealBtn = await screen.findByRole("button", {
      name: /unseal vault/i,
    });
    await user.click(unsealBtn);
    expect(
      screen.getByRole("heading", { name: /unseal vault/i }),
    ).toBeInTheDocument();
  });

  it("asks the server whether machine identity is required and runs the gate when it is", async () => {
    const calls: string[] = [];
    mockInvoke.mockImplementation((cmd: string) => {
      calls.push(cmd);
      switch (cmd) {
        case "list_vault_profiles":
          return Promise.resolve({
            vaults: [
              {
                id: "v1",
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
            lastUsedId: null,
          });
        case "connect_remote":
          return Promise.resolve(null);
        // The server reports it requires machine identity — the connect flow
        // must obey this regardless of any client-side setting.
        case "ferrogate_requirement":
          return Promise.resolve({
            require_machine_identity: true,
            expected_audience: "https://vault.example.com:8200",
            trust_domain: "ferrogate.test",
          });
        case "get_selected_node":
          return Promise.resolve(null);
        case "set_last_used_vault":
          return Promise.resolve(null);
        // Gate runs: a pending enrolment parks the flow (no navigation).
        case "ferrogate_machine_login":
          return Promise.resolve({
            spiffe_id: "spiffe://ferrogate.test/host/x",
            authenticated: false,
            enrolment: "pending",
            message: "enrolment_pending",
            client_token: "",
            policies: [],
            lease_duration: 0,
          });
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => expect(screen.getByText("Prod")).toBeInTheDocument());
    await userEvent.click(screen.getByText("Prod"));

    // It consulted the server, then ran the machine gate purely off that answer.
    await waitFor(() => expect(calls).toContain("ferrogate_requirement"));
    await waitFor(() => expect(calls).toContain("ferrogate_machine_login"));
  });

  it("skips the machine gate when the server does not require it", async () => {
    const calls: string[] = [];
    mockInvoke.mockImplementation((cmd: string) => {
      calls.push(cmd);
      switch (cmd) {
        case "list_vault_profiles":
          return Promise.resolve({
            vaults: [
              {
                id: "v1",
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
            lastUsedId: null,
          });
        case "connect_remote":
          return Promise.resolve(null);
        case "ferrogate_requirement":
          return Promise.resolve({
            require_machine_identity: false,
            expected_audience: "",
            trust_domain: "",
          });
        case "get_selected_node":
          return Promise.resolve(null);
        case "set_last_used_vault":
          return Promise.resolve(null);
        // tryResumeSession after the (skipped) gate — no cached session.
        case "get_cached_session":
          return Promise.resolve(null);
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
    const { ConnectPage } = await import("../routes/ConnectPage");
    renderWithProviders(<ConnectPage />);

    await waitFor(() => expect(screen.getByText("Prod")).toBeInTheDocument());
    await userEvent.click(screen.getByText("Prod"));

    await waitFor(() => expect(calls).toContain("ferrogate_requirement"));
    // The gate never runs when the server says machine identity isn't required.
    expect(calls).not.toContain("ferrogate_machine_login");
  });
});
