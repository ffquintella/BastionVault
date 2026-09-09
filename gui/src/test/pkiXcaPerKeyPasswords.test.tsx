import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
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
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: () => Promise.resolve("/Users/op/Downloads/fgv_certificates_internos.xdb"),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----";
const KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIkey\n-----END PRIVATE KEY-----";

/** Two `ptPrivate` keys — the shape 443-of-551 real rows have. `k-a` is
 *  paired with a leaf cert so the cert row can advertise the locked key. */
function meta(id: number, item_type: string, name: string) {
  return { id, item_type, parent: 0, name, comment: "" };
}

interface PreviewFixture {
  summary: Record<string, unknown>;
  items: Record<string, unknown>[];
  decryption_failures: Array<{ name: string; reason: string }>;
  ownpass_keys: string[];
}

function lockedPreview(): PreviewFixture {
  return {
    summary: {
      format_version: "v2.4",
      issuer_count: 0,
      leaf_count: 1,
      csr_count: 0,
      crl_count: 0,
      template_count: 0,
      key_count: 2,
      skipped: [],
    },
    items: [
      {
        meta: meta(1, "cert", "leaf-a"),
        pem: CERT_PEM,
        subject: "CN=leaf-a.example.com",
        decrypt: "not_encrypted",
        has_own_pass: false,
        paired_item_id: 2,
        is_ca: false,
        signs_others: false,
      },
      {
        meta: meta(2, "private_key", "key with own pass A"),
        pem: null,
        decrypt: "wrong_password",
        has_own_pass: true,
        paired_item_id: 1,
      },
      {
        meta: meta(3, "private_key", "key with own pass B"),
        pem: null,
        decrypt: "wrong_password",
        has_own_pass: true,
        paired_item_id: null,
      },
    ],
    decryption_failures: [
      { name: "key with own pass A", reason: "wrong_password" },
      { name: "key with own pass B", reason: "wrong_password" },
    ],
    ownpass_keys: ["key with own pass A", "key with own pass B"],
  };
}

/** Same database, previewed again with the right per-key password: both
 *  keys open. */
function unlockedPreview() {
  const p = lockedPreview();
  p.items[1] = { ...p.items[1], pem: KEY_PEM, decrypt: "ok" };
  p.items[2] = { ...p.items[2], pem: KEY_PEM, decrypt: "ok" };
  p.decryption_failures = [];
  return p;
}

function b64(obj: unknown): string {
  return btoa(JSON.stringify(obj));
}

function invokeInput(call: unknown[]): Record<string, unknown> {
  const args = call[1] as { inputB64: string };
  return JSON.parse(atob(args.inputB64));
}

/** Every `plugins_invoke` gets the next preview in the queue. */
function installMocks(previews: unknown[]) {
  const queue = [...previews];
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve({
          plugins: [{ name: "xca-import", version: "0.1.22" }],
        });
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [] });
      case "pki_list_certs":
        return Promise.resolve([]);
      case "pki_list_keys":
        return Promise.resolve([]);
      case "read_local_file_b64":
        return Promise.resolve("eGRiLWJ5dGVz");
      case "plugins_invoke":
        return Promise.resolve({
          status: "success",
          plugin_status_code: 0,
          fuel_consumed: 0,
          response_b64: b64(queue.length > 1 ? queue.shift() : queue[0]),
        });
      default:
        return Promise.resolve(null);
    }
  });
}

async function openPreview(user: ReturnType<typeof userEvent.setup>) {
  render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await user.click(await screen.findByRole("button", { name: "Import XCA" }));
  await user.click(await screen.findByRole("button", { name: "Browse…" }));
  await user.click(await screen.findByRole("button", { name: "Preview" }));
}

describe("XCA import — per-key passwords", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("signals locked keys and offers skip or a password per key", async () => {
    installMocks([lockedPreview()]);
    const user = userEvent.setup();
    await openPreview(user);

    // The dedicated section lists both `ptPrivate` keys with their own
    // password field, and the header counts what is left.
    expect(
      await screen.findByRole("heading", { name: "Keys with their own password" }),
    ).toBeTruthy();
    expect(screen.getByText("2 of 2 locked")).toBeTruthy();
    expect(
      screen.getByLabelText("Password for key with own pass A"),
    ).toBeTruthy();
    expect(
      screen.getByLabelText("Password for key with own pass B"),
    ).toBeTruthy();

    // The table says what happens if the operator does nothing: the keys
    // are unchecked (skipped) and the paired cert imports cert-only.
    expect(screen.getByTestId("xca-locked-note").textContent).toContain(
      "leave them unchecked to skip",
    );
    // Each locked key is flagged twice on purpose: once in the section
    // that takes the password, once on its own row in the import table.
    const table = screen.getByRole("table");
    expect(within(table).getAllByText("locked — wrong_password").length).toBe(2);
    expect(within(table).getAllByRole("button", { name: "Enter password" }).length).toBe(
      3,
    );
    expect(within(table).getByText("key locked — cert only")).toBeTruthy();

    // Locked keys start unchecked; the decryptable cert starts checked.
    const boxes = screen.getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.filter((b) => b.checked).length).toBe(1);
  });

  it("applies one password to all remaining keys and re-previews", async () => {
    installMocks([lockedPreview(), unlockedPreview()]);
    const user = userEvent.setup();
    await openPreview(user);
    await screen.findByText("2 of 2 locked");

    await user.type(
      screen.getByLabelText("Password for all remaining locked keys"),
      "pfx-batch-2026",
    );
    await user.click(screen.getByRole("button", { name: "Apply to 2 remaining" }));
    await user.click(
      screen.getByRole("button", { name: "Re-preview with passwords" }),
    );

    // Both key names go out in `per_key_passwords`, keyed by item name.
    await waitFor(() => {
      const calls = mockInvoke.mock.calls.filter((c) => c[0] === "plugins_invoke");
      expect(calls.length).toBe(2);
      expect(invokeInput(calls[1]).per_key_passwords).toEqual({
        "key with own pass A": "pfx-batch-2026",
        "key with own pass B": "pfx-batch-2026",
      });
    });

    // The re-preview reports what moved, and the keys are now selectable.
    const diff = await screen.findByTestId("xca-unlock-diff");
    expect(diff.textContent).toContain("2 key(s) unlocked");
    expect(screen.getByText("2 unlocked")).toBeTruthy();
    await waitFor(() => {
      const boxes = screen.getAllByRole("checkbox") as HTMLInputElement[];
      expect(boxes.filter((b) => b.checked).length).toBe(3);
    });
  });

  it("sends no per_key_passwords when none were typed, and clears them", async () => {
    installMocks([lockedPreview()]);
    const user = userEvent.setup();
    await openPreview(user);
    await screen.findByText("2 of 2 locked");

    const first = mockInvoke.mock.calls.filter((c) => c[0] === "plugins_invoke")[0];
    expect(invokeInput(first).per_key_passwords).toBeUndefined();

    // Typed passwords live only as long as the preview does.
    const field = screen.getByLabelText(
      "Password for key with own pass A",
    ) as HTMLInputElement;
    await user.type(field, "secret");
    expect(field.value).toBe("secret");
    await user.click(screen.getByRole("button", { name: "Clear passwords" }));
    expect(
      (screen.getByLabelText("Password for key with own pass A") as HTMLInputElement)
        .value,
    ).toBe("");
  });
});
