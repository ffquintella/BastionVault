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
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const SERIAL = "1a:2b:3c:4d";
const KEY = {
  key_id: "key-uuid-1",
  name: "imported-leaf-key",
  key_type: "ec",
  key_bits: 256,
  public_key: "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----",
  source: "imported",
  exported: false,
  created_at: 1_700_000_000,
  issuer_ref_count: 0,
  cert_ref_count: 0,
};
const BASE_CERT = {
  serial_number: SERIAL,
  certificate: "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----",
  issued_at: 1_700_000_000,
  revoked_at: null,
  common_name: "assoc.example.com",
  not_after: 1_700_100_000,
  is_orphaned: true,
  source: "pkcs12-import",
  issuer_id: "",
  issuer_dn: "CN=Ext CA",
  san_dns: [],
  san_ip: [],
  san_email: [],
  san_uri: [],
  key_usages: [],
  ext_key_usages: [],
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

/** Base command mocks; `certOverrides` tweaks the read_cert record. */
function installMocks(certOverrides: Record<string, unknown> = {}) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [] });
      case "pki_list_certs":
        return Promise.resolve([SERIAL]);
      case "pki_read_cert":
        return Promise.resolve({ ...BASE_CERT, ...certOverrides });
      case "pki_list_keys":
        return Promise.resolve([KEY.key_id]);
      case "pki_read_key":
        return Promise.resolve(KEY);
      case "pki_associate_key":
        return Promise.resolve(null);
      case "pki_clear_cert_key":
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  });
}

async function selectCert(user: ReturnType<typeof userEvent.setup>) {
  renderPage();
  await user.click(await screen.findByRole("button", { name: "Certificates" }));
  await user.click(await screen.findByText(SERIAL));
}

describe("PKI key ↔ certificate association", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("associates a managed key with an unbound (orphan) cert", async () => {
    installMocks({ is_orphaned: true });
    const user = userEvent.setup();
    await selectCert(user);

    // Detail shows no binding + an "Associate key" action.
    expect(await screen.findByText("none associated")).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "Associate key" }));

    const heading = await screen.findByRole("heading", {
      name: "Associate a managed key",
    });
    const panel = heading.closest("div")!.parentElement as HTMLElement;
    await user.click(within(panel).getByRole("button", { name: "Associate" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_associate_key");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        mount: "pki",
        serial: SERIAL,
        keyRef: KEY.key_id,
      });
    });
  });

  it("shows the bound key and clears it on confirm", async () => {
    installMocks({ key_id: KEY.key_id, key_name: KEY.name });
    const user = userEvent.setup();
    await selectCert(user);

    // Bound key surfaces by name; actions read "Change key" + "Clear key".
    expect(await screen.findByText(KEY.name)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change key" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Clear key" }));

    // Confirm the destructive clear.
    await user.click(await screen.findByRole("button", { name: "Clear" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_clear_cert_key");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({ mount: "pki", serial: SERIAL });
    });
  });
});
