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
            cmis_spki_pins: [],
            static_jwks: "",
            accept_svid: false,
            clock_leeway_secs: 60,
            default_token_ttl: 0,
            cmis_tls_enable: true,
            jwks_refresh_secs: 60,
            bootstrap_root_auto_approve: true,
            bootstrap_policies: ["default"],
          });
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
    const approves = screen.getAllByRole("button", { name: /^approve$/i });
    await user.click(approves[approves.length - 1]);

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "ferrogate_approve",
        expect.objectContaining({ id: PENDING.id, policies: "default" }),
      );
    });
  });
});
