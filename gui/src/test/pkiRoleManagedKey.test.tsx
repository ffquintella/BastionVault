import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import { PkiPage } from "../routes/PkiPage";

// Role option `manage_private_key`: issue-generated leaf keys are kept in
// the managed key store and bound to the cert. The engine refuses it with
// `no_store`, so the form must not let the operator build that pair.

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: () => Promise.resolve(null),
  open: () => Promise.resolve(null),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const LABEL = "manage_private_key (store key in Keys, exportable)";

const STORED_ROLE = {
  ttl: "720h",
  max_ttl: "2160h",
  key_type: "ec",
  key_bits: 0,
  allow_localhost: true,
  allow_any_name: true,
  allow_subdomains: false,
  allow_bare_domains: false,
  allow_ip_sans: true,
  server_flag: true,
  client_flag: true,
  use_csr_sans: true,
  use_csr_common_name: true,
  key_usage: ["DigitalSignature"],
  ext_key_usage: [],
  country: "",
  province: "",
  locality: "",
  organization: "",
  ou: "",
  no_store: false,
  generate_lease: false,
  issuer_ref: "",
  allow_key_reuse: false,
  allowed_key_refs: [],
  manage_private_key: true,
  allowed_domains: [],
  allow_glob_domains: false,
  acme_enabled: true,
  allow_email_sans: false,
  allowed_email_domains: [],
};

function installMocks(roles: string[]) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [] });
      case "pki_list_roles":
        return Promise.resolve(roles);
      case "pki_read_role":
        return Promise.resolve(STORED_ROLE);
      case "pki_write_role":
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  });
}

async function openRolesTab(user: ReturnType<typeof userEvent.setup>) {
  render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await user.click(await screen.findByRole("button", { name: "Roles" }));
}

describe("PKI role — manage_private_key", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("sends manage_private_key=true when ticked on the create form", async () => {
    installMocks([]);
    const user = userEvent.setup();
    await openRolesTab(user);

    await user.click(await screen.findByRole("button", { name: "+ Create role" }));
    await user.type(await screen.findByLabelText("Role name"), "kept");
    const toggle = await screen.findByLabelText(LABEL);
    expect((toggle as HTMLInputElement).checked).toBe(false);
    await user.click(toggle);
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_write_role");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        mount: "pki",
        name: "kept",
        config: { manage_private_key: true, no_store: false },
      });
    });
  });

  it("shows the stored value read-only and blocks pairing it with no_store", async () => {
    installMocks(["kept"]);
    const user = userEvent.setup();
    await openRolesTab(user);
    await user.click(await screen.findByRole("button", { name: "kept" }));

    // Read-only view reflects the stored role.
    const toggle = (await screen.findByLabelText(LABEL)) as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    expect(toggle.disabled).toBe(true);

    // Editing: no_store cannot be switched on while the key is managed …
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const noStore = screen.getByLabelText("no_store") as HTMLInputElement;
    expect(noStore.disabled).toBe(true);

    // … and becomes available again once manage_private_key is off.
    await user.click(screen.getByLabelText(LABEL));
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).checked).toBe(false);
    expect((screen.getByLabelText("no_store") as HTMLInputElement).disabled).toBe(false);
    await user.click(screen.getByLabelText("no_store"));
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).disabled).toBe(true);

    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_write_role");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        name: "kept",
        config: { manage_private_key: false, no_store: true },
      });
    });
  });
});
