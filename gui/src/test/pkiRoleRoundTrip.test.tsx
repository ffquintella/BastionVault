import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import { PkiPage } from "../routes/PkiPage";
import type { PkiRoleConfig } from "../lib/types";

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

/** A smart-card logon role as the API/CLI would have written it. */
const SMARTCARD_ROLE: PkiRoleConfig = {
  ttl: "720h",
  max_ttl: "2160h",
  key_type: "rsa",
  key_bits: 2048,
  allow_localhost: false,
  allow_any_name: true,
  allow_subdomains: false,
  allow_bare_domains: false,
  allow_ip_sans: false,
  server_flag: false,
  client_flag: true,
  use_csr_sans: true,
  use_csr_common_name: true,
  key_usage: ["DigitalSignature", "KeyEncipherment"],
  ext_key_usage: [],
  country: "",
  province: "",
  locality: "",
  organization: "Corp",
  ou: "",
  no_store: false,
  generate_lease: false,
  issuer_ref: "",
  allow_key_reuse: false,
  allowed_key_refs: [],
  manage_private_key: false,
  allowed_domains: [],
  allow_glob_domains: false,
  acme_enabled: false,
  allow_email_sans: false,
  allowed_email_domains: [],
  allow_upn_sans: true,
  allowed_upn_domains: ["corp.example.com"],
  ext_key_usage_oids: ["1.3.6.1.4.1.311.20.2.2"],
  allow_ad_sid: true,
  ad_sid: "S-1-5-21-1004336348-1177238915-682003330-512",
  signature_bits: 384,
  not_before_duration: 120,
};

function installMocks() {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [] });
      case "pki_list_roles":
        return Promise.resolve(["smartcard"]);
      case "pki_read_role":
        return Promise.resolve({ ...SMARTCARD_ROLE });
      default:
        return Promise.resolve(null);
    }
  });
}

describe("PKI role editor round-trip", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("keeps AD smart-card fields and non-edited fields when a role is saved", async () => {
    installMocks();
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/pki"]}>
        <ToastProvider>
          <PkiPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await user.click(await screen.findByRole("button", { name: "Roles" }));
    await user.click(await screen.findByRole("button", { name: "smartcard" }));
    await user.click(await screen.findByRole("button", { name: "Edit" }));
    await user.click(await screen.findByRole("button", { name: "Save" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_write_role");
      expect(call).toBeTruthy();
      // Saving without touching anything must send back exactly what was
      // read — a field missing here is reset to its default by the engine.
      expect(call![1]).toEqual({ mount: "pki", name: "smartcard", config: SMARTCARD_ROLE });
    });
  });

  it("shows the AD smart-card fields in the editor", async () => {
    installMocks();
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/pki"]}>
        <ToastProvider>
          <PkiPage />
        </ToastProvider>
      </MemoryRouter>,
    );

    await user.click(await screen.findByRole("button", { name: "Roles" }));
    await user.click(await screen.findByRole("button", { name: "smartcard" }));

    expect(await screen.findByDisplayValue("corp.example.com")).toBeTruthy();
    expect(screen.getByDisplayValue("1.3.6.1.4.1.311.20.2.2")).toBeTruthy();
    expect(screen.getByDisplayValue(SMARTCARD_ROLE.ad_sid)).toBeTruthy();
  });
});
