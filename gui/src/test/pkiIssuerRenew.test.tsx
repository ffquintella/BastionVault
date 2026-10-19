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

// The field report: an imported RSA root, backed by a managed key, expired.
const EXPIRED_AT = 1_754_352_000; // 2025-08-05
const RENEWED_UNTIL = 2_069_712_000; // 2035-08-03
const ROOT = { id: "issuer-uuid-1", name: "fgv-root-ca-v1", is_default: true };

function detail(notAfter: number, keyId: string) {
  return {
    id: ROOT.id,
    name: ROOT.name,
    certificate: "-----BEGIN CERTIFICATE-----\nMIIca\n-----END CERTIFICATE-----",
    key_type: "rsa",
    common_name: "fgv-root-ca-v1",
    not_after: notAfter,
    ca_kind: "imported",
    is_default: true,
    usage: ["issuing-certificates", "crl-signing"],
    key_id: keyId,
  };
}

/** `keyId = ""` models a key-less trust anchor. */
function installMocks({ keyId = "key-uuid-1", adminCaps = true } = {}) {
  let notAfter = EXPIRED_AT;
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "plugins_list":
        return Promise.resolve([]);
      case "pki_list_mounts":
        return Promise.resolve([{ path: "pki/", mount_type: "pki" }]);
      case "pki_list_issuers":
        return Promise.resolve({ issuers: [ROOT] });
      case "pki_read_issuer":
        return Promise.resolve(detail(notAfter, keyId));
      case "capabilities_self":
        return Promise.resolve({ paths: { "pki/keys": adminCaps ? ["list", "update"] : ["read"] } });
      case "pki_renew_issuer":
        notAfter = RENEWED_UNTIL;
        return Promise.resolve({
          issuer_id: ROOT.id,
          issuer_name: ROOT.name,
          certificate: "-----BEGIN CERTIFICATE-----\nMIInew\n-----END CERTIFICATE-----",
          serial_number: "0a0b",
          not_before: RENEWED_UNTIL - 315_360_000,
          not_after: RENEWED_UNTIL,
          previous_serial_number: "0102",
          previous_not_after: EXPIRED_AT,
          signed_by: "self",
          signed_by_issuer_id: ROOT.id,
          ttl_clamped: false,
        });
      default:
        return Promise.resolve(null);
    }
  });
}

function renderPage() {
  render(
    <MemoryRouter initialEntries={["/pki"]}>
      <ToastProvider>
        <PkiPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function renewCalls() {
  return mockInvoke.mock.calls.filter((c) => c[0] === "pki_renew_issuer");
}

describe("PKI issuer renew", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    useNamespaceStore.setState({ active: "", namespaces: [], loaded: true });
  });

  it("renews an expired key-backed issuer with the TTL the operator typed", async () => {
    installMocks();
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText(/2025-08-05 .* UTC \(expired\)/)).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "Renew" }));
    const heading = await screen.findByRole("heading", { name: "Renew issuer certificate" });
    const modal = heading.closest("div")!.parentElement as HTMLElement;

    await user.type(within(modal).getByLabelText("Validity (TTL)"), "87600h");
    await user.click(within(modal).getByRole("button", { name: "Renew" }));

    await waitFor(() => expect(renewCalls()).toHaveLength(1));
    expect(renewCalls()[0][1]).toEqual({ mount: "pki", reference: ROOT.id, ttl: "87600h" });
    expect(await screen.findByText(/renewed until 2035-08-03 .*\(re-signed with its own key\)/)).toBeTruthy();
    // The detail is re-read, so the new expiry replaces the expired one.
    expect(await screen.findByText(/^2035-08-03 .* UTC$/)).toBeTruthy();
    expect(screen.queryByText(/\(expired\)/)).toBeNull();
  });

  it("sends no ttl when the field is left empty, keeping the validity span", async () => {
    installMocks();
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Renew" }));
    const heading = await screen.findByRole("heading", { name: "Renew issuer certificate" });
    const modal = heading.closest("div")!.parentElement as HTMLElement;
    await user.click(within(modal).getByRole("button", { name: "Renew" }));

    await waitFor(() => expect(renewCalls()).toHaveLength(1));
    expect(renewCalls()[0][1]).toEqual({ mount: "pki", reference: ROOT.id, ttl: null });
  });

  it("does not offer Renew for a key-less trust anchor", async () => {
    installMocks({ keyId: "" });
    renderPage();

    expect(await screen.findByRole("button", { name: "Rename" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Renew" })).toBeNull();
  });

  it("does not offer Renew to a caller who cannot administer the mount", async () => {
    useAuthStore.setState({ token: "t", policies: ["pki-user"], isAuthenticated: true });
    installMocks({ adminCaps: false });
    renderPage();

    expect(await screen.findByRole("button", { name: "Export" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Renew" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Rename" })).toBeNull();
  });
});
