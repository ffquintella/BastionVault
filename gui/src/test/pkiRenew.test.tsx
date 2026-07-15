import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import { PkiPage } from "../routes/PkiPage";

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
// Isolate the page from the Layout chrome (nav/store effects).
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const SERIAL = "1a:2b:3c:4d";
const CERT = {
  serial_number: SERIAL,
  certificate: "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----",
  issued_at: 1_700_000_000,
  revoked_at: null,
  common_name: "api.example.com",
  not_after: 1_700_100_000,
  is_orphaned: false,
  source: "",
  issuer_id: "issuer-uuid-1",
  issuer_dn: "CN=Test Root CA",
  san_dns: ["api.example.com", "api-alt.example.com"],
  san_ip: ["10.0.0.1"],
  san_email: [],
  san_uri: [],
  key_usages: ["digitalSignature"],
  ext_key_usages: ["serverAuth"],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("PKI certificate renewal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    // A super-admin policy short-circuits the per-mount capability probe.
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });

    mockInvoke.mockImplementation((cmd: string, _args?: unknown) => {
      switch (cmd) {
        case "plugins_list":
          return Promise.resolve([]);
        case "pki_list_mounts":
          return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
        case "pki_list_issuers":
          return Promise.resolve({
            issuers: [{ id: "issuer-uuid-1", name: "Test Root CA", is_default: true }],
          });
        case "pki_list_certs":
          return Promise.resolve([SERIAL]);
        case "pki_read_cert":
          return Promise.resolve(CERT);
        case "pki_list_roles":
          return Promise.resolve(["web-server"]);
        case "pki_issue_cert":
          return Promise.resolve({
            certificate: "-----BEGIN CERTIFICATE-----\nNEWcert\n-----END CERTIFICATE-----",
            issuing_ca: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            private_key: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
            private_key_type: "ec",
            serial_number: "99:88:77:66",
            issuer_id: "issuer-uuid-1",
            ca_chain: [],
            key_id: "",
          });
        case "pki_revoke_cert":
          return Promise.resolve({
            revocation_time: 1_700_050_000,
            serial_number: SERIAL,
            issuer_id: "issuer-uuid-1",
          });
        default:
          return Promise.resolve(null);
      }
    });
  });

  async function openRenewModal(user: ReturnType<typeof userEvent.setup>) {
    renderPage();
    // Switch to the Certificates tab.
    await user.click(await screen.findByRole("button", { name: "Certificates" }));
    // Select the cert row to open the detail panel.
    await user.click(await screen.findByText(SERIAL));
    // The detail panel's Renew button opens the modal.
    await user.click(await screen.findByRole("button", { name: "Renew" }));
    // The shared Modal has no role="dialog"; scope to its panel via the
    // title heading (header <h2> → header div → panel div) so queries
    // don't collide with the detail panel behind it.
    const heading = await screen.findByRole("heading", {
      name: "Renew certificate",
    });
    return heading.closest("div")!.parentElement as HTMLElement;
  }

  it("pre-fills the renew form from the selected certificate", async () => {
    const user = userEvent.setup();
    const dialog = await openRenewModal(user);

    // CN pre-filled from the cert.
    expect(within(dialog).getByDisplayValue("api.example.com")).toBeTruthy();
    // DNS SANs joined comma-separated.
    expect(
      within(dialog).getByDisplayValue("api.example.com, api-alt.example.com"),
    ).toBeTruthy();
    // IP SANs pre-filled.
    expect(within(dialog).getByDisplayValue("10.0.0.1")).toBeTruthy();
    // Issuer defaults to the original signer.
    expect(within(dialog).getByDisplayValue("issuer-uuid-1")).toBeTruthy();
  });

  it("re-issues under the chosen role and shows the new cert + key", async () => {
    const user = userEvent.setup();
    const dialog = await openRenewModal(user);

    await user.click(within(dialog).getByRole("button", { name: "Renew" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_issue_cert");
      expect(call).toBeTruthy();
      const req = (call![1] as { request: Record<string, unknown> }).request;
      expect(req.mount).toBe("pki");
      expect(req.role).toBe("web-server");
      expect(req.common_name).toBe("api.example.com");
      expect(req.alt_names).toBe("api.example.com, api-alt.example.com");
      expect(req.ip_sans).toBe("10.0.0.1");
      expect(req.issuer_ref).toBe("issuer-uuid-1");
    });

    // New serial + private key surfaced once so the operator can copy it.
    expect(await within(dialog).findByText("99:88:77:66")).toBeTruthy();
    expect(
      within(dialog).getByDisplayValue(/BEGIN PRIVATE KEY/),
    ).toBeTruthy();

    // No revoke unless explicitly requested.
    expect(mockInvoke.mock.calls.some((c) => c[0] === "pki_revoke_cert")).toBe(false);
  });

  it("revokes the old serial when the toggle is enabled", async () => {
    const user = userEvent.setup();
    const dialog = await openRenewModal(user);

    await user.click(
      within(dialog).getByRole("checkbox"),
    );
    await user.click(within(dialog).getByRole("button", { name: "Renew" }));

    await waitFor(() => {
      const revoke = mockInvoke.mock.calls.find((c) => c[0] === "pki_revoke_cert");
      expect(revoke).toBeTruthy();
      expect((revoke![1] as { serial: string }).serial).toBe(SERIAL);
    });
  });
});
