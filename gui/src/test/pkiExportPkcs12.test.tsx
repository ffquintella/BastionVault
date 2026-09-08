import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";
import { PkiPage } from "../routes/PkiPage";

const mockInvoke = vi.fn();
const mockSave = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: (...args: unknown[]) => mockSave(...args),
  open: () => Promise.resolve(null),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const SERIAL = "1a:2b:3c:4d";
const CERT = {
  serial_number: SERIAL,
  certificate: "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----",
  issued_at: 1_700_000_000,
  revoked_at: null,
  common_name: "export.example.com",
  not_after: 1_700_100_000,
  is_orphaned: false,
  source: "issued",
  issuer_id: "issuer-1",
  issuer_dn: "CN=Root",
  san_dns: [],
  san_ip: [],
  san_email: [],
  san_uri: [],
  key_usages: [],
  ext_key_usages: [],
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
      case "pki_list_certs":
        return Promise.resolve([SERIAL]);
      case "pki_read_cert":
        return Promise.resolve(CERT);
      case "pki_list_keys":
        return Promise.resolve([]);
      case "pki_export_cert_to_path":
        return Promise.resolve({
          format: "pkcs12",
          path: "/tmp/leaf.p12",
          bytes_written: 1410,
          includes_private_key: true,
          backup_mode: false,
        });
      case "pki_export_cert":
        return Promise.resolve({
          format: "pem",
          filename_extension: "pem",
          body: "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----",
          body_encoding: "utf8",
          includes_private_key: false,
        });
      default:
        return Promise.resolve(null);
    }
  });
}

async function openExportModal(user: ReturnType<typeof userEvent.setup>) {
  render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await user.click(await screen.findByRole("button", { name: "Certificates" }));
  await user.click(await screen.findByText(SERIAL));
  await user.click(await screen.findByRole("button", { name: "Export" }));
  return screen.findByRole("heading", { name: "Export certificate" });
}

describe("PKI export modal — PKCS#12 is a file export", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockSave.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("asks where to save, then writes the .p12 through the host", async () => {
    installMocks();
    mockSave.mockResolvedValue("/tmp/leaf.p12");
    const user = userEvent.setup();
    await openExportModal(user);

    await user.selectOptions(
      await screen.findByLabelText("Format"),
      "pkcs12",
    );
    await user.click(screen.getByRole("checkbox"));
    await user.type(
      await screen.findByLabelText("PKCS#12 password"),
      "s3cret-bag",
    );
    await user.click(
      screen.getByRole("button", { name: "Choose file & export…" }),
    );

    // The destination is picked before anything is exported.
    await waitFor(() => expect(mockSave).toHaveBeenCalledTimes(1));
    expect(mockSave.mock.calls[0][0]).toMatchObject({
      defaultPath: expect.stringContaining(".p12"),
    });

    // The host does the export and the write; the payload never comes back.
    await waitFor(() => {
      const call = mockInvoke.mock.calls.find(
        (c) => c[0] === "pki_export_cert_to_path",
      );
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({
        targetPath: "/tmp/leaf.p12",
        request: {
          mount: "pki",
          serial: SERIAL,
          format: "pkcs12",
          include_private_key: true,
          password: "s3cret-bag",
        },
      });
    });
    // And never through the preview command, which would put the bag —
    // private key included — in the webview.
    expect(
      mockInvoke.mock.calls.some((c) => c[0] === "pki_export_cert"),
    ).toBe(false);
    expect(await screen.findByText("/tmp/leaf.p12")).toBeTruthy();
  });

  it("exports nothing when the save dialog is cancelled", async () => {
    installMocks();
    mockSave.mockResolvedValue(null);
    const user = userEvent.setup();
    await openExportModal(user);

    await user.selectOptions(await screen.findByLabelText("Format"), "pkcs12");
    await user.type(
      await screen.findByLabelText("PKCS#12 password"),
      "s3cret-bag",
    );
    await user.click(
      screen.getByRole("button", { name: "Choose file & export…" }),
    );

    await waitFor(() => expect(mockSave).toHaveBeenCalledTimes(1));
    expect(
      mockInvoke.mock.calls.some((c) => c[0] === "pki_export_cert_to_path"),
    ).toBe(false);
  });

  it("refuses a PKCS#12 export with no password, before opening the dialog", async () => {
    installMocks();
    const user = userEvent.setup();
    await openExportModal(user);

    await user.selectOptions(await screen.findByLabelText("Format"), "pkcs12");
    await user.click(
      screen.getByRole("button", { name: "Choose file & export…" }),
    );

    expect(
      await screen.findByText("PKCS#12 requires a password."),
    ).toBeTruthy();
    expect(mockSave).not.toHaveBeenCalled();
  });

  it("keeps PEM on the preview path", async () => {
    installMocks();
    const user = userEvent.setup();
    await openExportModal(user);

    // Two buttons read "Export": the detail panel's, which opened the
    // modal, and the modal's own submit. The latter is the last one.
    const exportButtons = screen.getAllByRole("button", { name: "Export" });
    await user.click(exportButtons[exportButtons.length - 1]);

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_export_cert");
      expect(call).toBeTruthy();
    });
    expect(mockSave).not.toHaveBeenCalled();
    // Text formats keep their in-window preview.
    expect(await screen.findByText(/Suggested extension/)).toBeTruthy();
  });
});
