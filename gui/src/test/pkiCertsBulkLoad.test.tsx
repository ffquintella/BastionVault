/**
 * The Certificates tab loads its rows from `pki/certs/info`, one page at a
 * time, rather than reading every serial individually.
 *
 * This is the fix for a production report: the old shape issued `1 + N`
 * requests on a single page load, which on a mount holding a few hundred
 * certificates crossed the server's per-IP abuse ceiling (200 req / 10 s)
 * and banned the operator for five minutes. See
 * `features/client-request-efficiency.md`.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
  save: () => Promise.resolve(null),
  open: () => Promise.resolve(null),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function summary(i: number) {
  return {
    serial_number: `serial-${String(i).padStart(4, "0")}`,
    common_name: `leaf${i}.example.com`,
    issued_at: 1_700_000_000,
    not_after: 1_900_000_000,
    revoked_at: null,
    is_orphaned: false,
    source: "",
    issuer_id: "issuer-uuid-1",
    issuer_dn: "CN=Test Root",
    key_id: "",
  };
}

/** Base command mocks every render of the page needs. */
function baseHandler(cmd: string) {
  switch (cmd) {
    case "plugins_list":
      return Promise.resolve([]);
    case "pki_list_mounts":
      return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
    case "pki_list_issuers":
      return Promise.resolve({
        issuers: [{ id: "issuer-uuid-1", name: "Test Root CA", is_default: true }],
      });
    case "pki_list_roles":
      return Promise.resolve([]);
    case "pki_list_keys":
      return Promise.resolve([]);
    default:
      return undefined;
  }
}

function renderPage() {
  useAuthStore.setState({ token: "root-token", isAuthenticated: true });
  useNamespaceStore.setState({ active: "" });
  render(
    <MemoryRouter>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

async function openCertificatesTab() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Certificates" }));
  return user;
}

describe("Certificates tab bulk load", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("walks cursor pages instead of reading each serial", async () => {
    // 1,200 certificates: three pages of 500, 500, 200. The old shape
    // would have issued 1,201 requests for the same table.
    const all = Array.from({ length: 1200 }, (_, i) => summary(i));
    const pageCalls: Array<{ after: string | null; limit: number | null }> = [];

    mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
      const base = baseHandler(cmd);
      if (base) return base;
      if (cmd === "pki_list_certs_info") {
        const after = (args?.after as string | null) ?? null;
        const limit = (args?.limit as number | null) ?? null;
        pageCalls.push({ after, limit });
        const start = after
          ? all.findIndex((r) => r.serial_number === after) + 1
          : 0;
        const records = all.slice(start, start + (limit ?? 100));
        const last = records[records.length - 1];
        const consumed = start + records.length;
        return Promise.resolve({
          records,
          total: all.length,
          next: consumed < all.length ? last.serial_number : "",
        });
      }
      if (cmd === "pki_list_certs" || cmd === "pki_read_cert") {
        throw new Error("must not fall back to the per-certificate read");
      }
      return Promise.resolve(null);
    });

    renderPage();
    await openCertificatesTab();

    await waitFor(() => expect(pageCalls.length).toBe(3));
    expect(pageCalls[0]).toEqual({ after: null, limit: 500 });
    expect(pageCalls[1].after).toBe("serial-0499");
    expect(pageCalls[2].after).toBe("serial-0999");

    // The rows made it into the table.
    expect(await screen.findByText("serial-0000")).toBeInTheDocument();
    expect(screen.getByText("leaf0.example.com")).toBeInTheDocument();
  });

  it("reports the real total when the inventory exceeds the load ceiling", async () => {
    // A page reporting a total far beyond what was loaded must say so: the
    // filter and the row pager both work over the loaded set, so a silently
    // truncated table would look complete.
    mockInvoke.mockImplementation((cmd: string) => {
      const base = baseHandler(cmd);
      if (base) return base;
      if (cmd === "pki_list_certs_info") {
        return Promise.resolve({
          records: Array.from({ length: 500 }, (_, i) => summary(i)),
          total: 40_000,
          next: "serial-0499",
        });
      }
      return Promise.resolve(null);
    });

    renderPage();
    await openCertificatesTab();

    expect(
      await screen.findByText(/Showing the first .* of .* certificates/),
    ).toBeInTheDocument();
    expect(screen.getByText(/40,000 certificates/)).toBeInTheDocument();
  });

  it("falls back to the per-certificate read on a server without the route", async () => {
    // Version skew: a newer GUI against a vault that predates the endpoint
    // must degrade in speed, not break.
    let readCerts = 0;
    mockInvoke.mockImplementation((cmd: string) => {
      const base = baseHandler(cmd);
      if (base) return base;
      switch (cmd) {
        case "pki_list_certs_info":
          return Promise.reject({
            message: "HTTP 404: Logical backend path not supported.",
          });
        case "pki_list_certs":
          return Promise.resolve(["serial-0000", "serial-0001"]);
        case "pki_read_cert":
          readCerts += 1;
          return Promise.resolve({
            ...summary(readCerts - 1),
            serial_number: `serial-000${readCerts - 1}`,
            certificate: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
          });
        default:
          return Promise.resolve(null);
      }
    });

    renderPage();
    await openCertificatesTab();

    expect(await screen.findByText("serial-0000")).toBeInTheDocument();
    await waitFor(() => expect(readCerts).toBe(2));
  });
});
