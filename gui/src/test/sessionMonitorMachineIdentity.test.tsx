import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

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

const REJECTED = { valid: false, reachable: true, ttl_seconds: null, expire_time: null };

function mockServer(requirement: Record<string, unknown>) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "token_status") return Promise.resolve(REJECTED);
    if (cmd === "ferrogate_requirement") return Promise.resolve(requirement);
    if (cmd === "list_sso_providers") return Promise.resolve({ enabled: false, providers: [] });
    return Promise.resolve(null);
  });
}

async function mountMonitor() {
  const { SessionMonitor } = await import("../components/SessionMonitor");
  render(
    <MemoryRouter>
      <ToastProvider>
        <SessionMonitor />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("SessionMonitor when the server requires machine identity", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({
      token: "hvs.plain-user-token",
      policies: ["default"],
      isAuthenticated: true,
      sessionExpired: false,
      sessionEndReason: null,
    });
  });

  // Regression: arming `require_machine_identity` makes the server refuse every
  // request from a token that is not machine-bound. `token_status` reports that
  // refusal as an invalid token, so the monitor told the operator their session
  // "expired" — nothing they could act on, and indistinguishable from a real
  // expiry. The cause must be named.
  it("ends the session with the machine-identity reason, not a plain expiry", async () => {
    mockServer({ advertised: true, require_machine_identity: true, expected_audience: "a", mia_environment: "" });
    await mountMonitor();

    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(false));
    expect(useAuthStore.getState().sessionEndReason).toBe("machine-identity");
    expect(await screen.findByText(/requires machine identity/i)).toBeInTheDocument();
  });

  it("still reports a plain expiry when machine identity is not required", async () => {
    mockServer({ advertised: true, require_machine_identity: false, expected_audience: "", mia_environment: "" });
    await mountMonitor();

    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(false));
    expect(useAuthStore.getState().sessionEndReason).toBe("expired");
  });

  // A failed requirement read comes back `advertised: false` with defaults.
  // That is "no answer", not "not required": falling back to a plain expiry is
  // the safe, pre-existing behaviour and must not claim a cause we did not see.
  it("falls back to a plain expiry when the requirement cannot be read", async () => {
    mockServer({ advertised: false, require_machine_identity: false, expected_audience: "", mia_environment: "" });
    await mountMonitor();

    await waitFor(() => expect(useAuthStore.getState().isAuthenticated).toBe(false));
    expect(useAuthStore.getState().sessionEndReason).toBe("expired");
  });
});

describe("LoginPage banner after the session ended", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "list_sso_providers" ? Promise.resolve({ enabled: false, providers: [] }) : Promise.reject(new Error(`unmocked: ${cmd}`)),
    );
  });

  it("explains a machine-identity ending instead of saying the session expired", async () => {
    useAuthStore.setState({
      token: null,
      policies: [],
      isAuthenticated: false,
      sessionExpired: true,
      sessionEndReason: "machine-identity",
    });
    const { LoginPage } = await import("../routes/LoginPage");
    render(
      <MemoryRouter>
        <ToastProvider>
          <LoginPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    expect(screen.getByText(/requires machine identity/i)).toBeInTheDocument();
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument();
  });
});

describe("LoginPage FIDO2 sign-in against a server that requires machine identity", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: null, policies: [], isAuthenticated: false, sessionExpired: false, sessionEndReason: null });
  });

  // The requirement is read from the server at sign-in time, not taken from the
  // connect-time snapshot, so a gate armed on a live connection is still seen.
  it("reads the requirement and attempts the machine binding for a non-root user", async () => {
    const { useVaultStore } = await import("../stores/vaultStore");
    useVaultStore.setState({
      mode: "Remote",
      remoteProfile: { name: "p", address: "https://v:8200", require_machine_identity: false } as never,
    });
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_sso_providers":
          return Promise.resolve({ enabled: false, providers: [] });
        case "fido2_native_login":
          return Promise.resolve({ token: "hvs.user", policies: ["administrator", "default"] });
        case "ferrogate_requirement":
          return Promise.resolve({ advertised: true, require_machine_identity: true, expected_audience: "aud", mia_environment: "" });
        case "ferrogate_machine_login":
          return Promise.resolve({ authenticated: false, client_token: "", policies: [], message: "MIA unavailable" });
        default:
          return Promise.resolve(null);
      }
    });
    const { LoginPage } = await import("../routes/LoginPage");
    const userEvent = (await import("@testing-library/user-event")).default;
    render(
      <MemoryRouter>
        <ToastProvider>
          <LoginPage />
        </ToastProvider>
      </MemoryRouter>,
    );
    await userEvent.type(screen.getByPlaceholderText("alice"), "alice");
    await userEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect(await screen.findByText(/MIA unavailable/)).toBeInTheDocument();
    const called = mockInvoke.mock.calls.map((c) => c[0]);
    expect(called).toContain("ferrogate_requirement");
    expect(called).toContain("ferrogate_machine_login");
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });
});
