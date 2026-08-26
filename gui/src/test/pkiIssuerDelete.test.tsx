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
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const DEFAULT_ISSUER = { id: "issuer-uuid-1", name: "default", is_default: true };
const SECOND_ISSUER = { id: "issuer-uuid-2", name: "uat-root", is_default: false };

function detailFor(summary: { id: string; name: string; is_default: boolean }) {
  return {
    id: summary.id,
    name: summary.name,
    certificate: "-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----",
    key_type: "ec",
    common_name: `${summary.name}.example.com`,
    not_after: 1_800_000_000,
    ca_kind: "root",
    is_default: summary.is_default,
    usage: ["issuing-certificates", "crl-signing"],
    key_id: "",
  };
}

/** `issuers` drives what `pki_list_issuers` reports for the mount. */
function installMocks(issuers: Array<typeof DEFAULT_ISSUER>) {
  mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers });
      case "pki_read_issuer": {
        const ref = args?.reference as string;
        const found = issuers.find((i) => i.id === ref) ?? issuers[0];
        return Promise.resolve(detailFor(found));
      }
      case "pki_delete_issuer":
        return Promise.resolve(null);
      default:
        return Promise.resolve(null);
    }
  });
}

/** Render the page and open the delete-issuer confirmation. */
async function openDeleteDialog(user: ReturnType<typeof userEvent.setup>) {
  render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await user.click(await screen.findByRole("button", { name: "Delete" }));
  const heading = await screen.findByRole("heading", { name: "Delete issuer?" });
  return heading.closest("div")!.parentElement as HTMLElement;
}

describe("PKI issuer delete", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("explains, and refuses to send, a delete of the default issuer with siblings", async () => {
    installMocks([DEFAULT_ISSUER, SECOND_ISSUER]);
    const user = userEvent.setup();
    const modal = await openDeleteDialog(user);

    // The engine answers 409 here; the dialog must say why up front
    // rather than letting the operator collect an error toast.
    expect(
      screen.getByText(/is this mount's default issuer and other issuers still exist/),
    ).toBeTruthy();
    const confirm = within(modal).getByRole("button", { name: "Delete" });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    await user.click(confirm);
    expect(mockInvoke.mock.calls.some((c) => c[0] === "pki_delete_issuer")).toBe(false);
  });

  it("deletes the default issuer when it is the only one", async () => {
    installMocks([DEFAULT_ISSUER]);
    const user = userEvent.setup();
    const modal = await openDeleteDialog(user);

    expect(screen.getByText(/Certs already issued by this issuer remain/)).toBeTruthy();
    const confirm = within(modal).getByRole("button", { name: "Delete" });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);

    await user.click(confirm);
    await waitFor(() => {
      const call = mockInvoke.mock.calls.find((c) => c[0] === "pki_delete_issuer");
      expect(call).toBeTruthy();
      expect(call![1]).toMatchObject({ mount: "pki", reference: DEFAULT_ISSUER.id });
    });
  });
});
