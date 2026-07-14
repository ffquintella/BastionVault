import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

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
// Isolate the page from the Layout chrome (nav/store effects) — we only
// exercise FerroGatePage's own logic here.
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function renderWithProviders(ui: React.ReactNode, { route = "/ferrogate" } = {}) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  );
}

const PENDING = {
  id: "a".repeat(64),
  spiffe_id: "spiffe://ferrogate.test/host/abc",
  status: "pending",
  policies: [],
  ttl_seconds: 0,
  ek_cert_sha384: "",
  policy_id: "",
  parent_svid: "33".repeat(48),
  first_seen_at: 1_700_000_000,
  approved_at: 0,
  approver: "",
  last_login_at: 0,
  last_login_ip: "",
  reject_reason: "",
  comment: "",
};

describe("FerroGatePage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    // Default to the root namespace — FerroGate's admin paths are root
    // paths, so the page only loads there. Individual tests override this.
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "ferrogate_list_machines":
          return Promise.resolve([PENDING]);
        case "ferrogate_read_config":
          return Promise.resolve({
            trust_domain: "ferrogate.test",
            expected_audience: "https://vault.example.com",
            jwks_source: "static_jwks",
            cmis_endpoint: "",
            cmis_srv: "",
            cmis_spki_pins: [],
            static_jwks: "",
            accept_svid: false,
            clock_leeway_secs: 60,
            default_token_ttl: 0,
            cmis_tls_enable: true,
            cmis_same_host: false,
            jwks_refresh_secs: 60,
            bootstrap_root_auto_approve: true,
            bootstrap_policies: ["default"],
          });
        case "list_policies":
          return Promise.resolve({ policies: ["administrator", "reader", "default", "root"] });
        // Catch-all for Layout / nav commands so nothing rejects.
        default:
          return Promise.resolve({});
      }
    });
  });

  it("lists a pending machine and offers Approve/Reject", async () => {
    const { FerroGatePage } = await import("../routes/FerroGatePage");
    renderWithProviders(<FerroGatePage />);

    await waitFor(() => {
      expect(screen.getByText("spiffe://ferrogate.test/host/abc")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: /^approve$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^reject$/i })).toBeInTheDocument();
  });

  it("hides machine admin in a child namespace and never calls the root-path list", async () => {
    useNamespaceStore.setState({ active: "dti/esi", namespaces: ["dti", "dti/esi"], loaded: true });

    const { FerroGatePage } = await import("../routes/FerroGatePage");
    renderWithProviders(<FerroGatePage />);

    await waitFor(() => {
      expect(screen.getByText(/managed at the root namespace/i)).toBeInTheDocument();
    });
    // The current namespace is named so the operator knows where they are.
    expect(screen.getByText(/dti\/esi/)).toBeInTheDocument();
    // Crucially, the page must NOT fire the root-path list (which would
    // 500 with "cannot access root path…" in a child namespace).
    expect(mockInvoke).not.toHaveBeenCalledWith("ferrogate_list_machines");
    // And it must not fall back to the misleading "not enabled" empty state.
    expect(screen.queryByText(/not enabled/i)).not.toBeInTheDocument();
  });

  it("surfaces a MIA refusal as a human-readable toast, not the raw opcode", async () => {
    const user = userEvent.setup();
    // The Rust boundary maps the refusal opcode through ErrorCode::describe()
    // and returns "MIA refused: <explanation>"; the raw variant ("CrlStale")
    // must never reach the toast.
    const refusal =
      "MIA refused: its revocation list (CRL) from CMIS is stale — the MIA fails closed; check that CMIS is reachable and publishing a fresh CRL";
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "ferrogate_list_machines":
          return Promise.resolve([]);
        case "ferrogate_read_config":
          return Promise.resolve({
            trust_domain: "ferrogate.test",
            expected_audience: "https://vault.example.com",
            jwks_source: "static_jwks",
            cmis_endpoint: "",
            cmis_srv: "",
            cmis_spki_pins: [],
            static_jwks: "",
            accept_svid: false,
            clock_leeway_secs: 60,
            default_token_ttl: 0,
            cmis_tls_enable: true,
            cmis_same_host: false,
            jwks_refresh_secs: 60,
            bootstrap_root_auto_approve: true,
            bootstrap_policies: ["default"],
          });
        case "ferrogate_machine_login":
          return Promise.reject({ message: refusal });
        default:
          return Promise.resolve({});
      }
    });

    const { FerroGatePage } = await import("../routes/FerroGatePage");
    renderWithProviders(<FerroGatePage />);

    await user.click(await screen.findByRole("button", { name: /machine login/i }));
    const loginBtn = await screen.findByRole("button", { name: /^log in$/i });
    await waitFor(() => expect(loginBtn).toBeEnabled());
    await user.click(loginBtn);

    await waitFor(() => {
      expect(screen.getByText(refusal)).toBeInTheDocument();
    });
    expect(screen.queryByText("CrlStale")).not.toBeInTheDocument();
  });

  it("approves a machine via the modal", async () => {
    const user = userEvent.setup();
    const { FerroGatePage } = await import("../routes/FerroGatePage");
    renderWithProviders(<FerroGatePage />);

    await waitFor(() => screen.getByText("spiffe://ferrogate.test/host/abc"));
    await user.click(screen.getByRole("button", { name: /^approve$/i }));

    // Modal open — now there are two exact "Approve" buttons (row + modal action).
    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: /^approve$/i }).length).toBeGreaterThan(1);
    });

    // Pick a policy from the multi-select (chips come from list_policies, so a
    // mistyped name can't be submitted). Selecting "reader" must send it verbatim.
    await user.click(await screen.findByRole("button", { name: /^reader$/i }));

    const approves = screen.getAllByRole("button", { name: /^approve$/i });
    await user.click(approves[approves.length - 1]);

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "ferrogate_approve",
        expect.objectContaining({ id: PENDING.id, policies: "reader" }),
      );
    });
  });

  it("saves the same-host CMIS flag from the Config tab", async () => {
    const user = userEvent.setup();
    const { FerroGatePage } = await import("../routes/FerroGatePage");
    renderWithProviders(<FerroGatePage />);

    await user.click(await screen.findByRole("button", { name: /^config$/i }));

    // Loaded as false from read_config; toggling it must round-trip on Save.
    const sameHost = await screen.findByRole("checkbox", {
      name: /CMIS is on the same host as the server/i,
    });
    expect(sameHost).not.toBeChecked();
    await user.click(sameHost);

    await user.click(screen.getByRole("button", { name: /save configuration/i }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "ferrogate_write_config",
        expect.objectContaining({ cmisSameHost: true, cmisTlsEnable: true }),
      );
    });
  });
});
