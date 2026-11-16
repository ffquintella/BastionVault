/**
 * Identity Provider page shell (T52 Phase 7): root-namespace only, a missing
 * `idp` mount is an enable prompt rather than an error, and the four tabs.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";
import { useNamespaceStore } from "../stores/namespaceStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

import { IdentityProviderPage } from "./IdentityProviderPage";

const CORE = {
  uid_min: 80000,
  uid_max: 999999,
  gid_min: 80000,
  gid_max: 999999,
  pinned: true,
  updated_at: null,
  uid_high_water: 80017,
  uid_used: 1,
  uid_retired: 0,
  gid_high_water: 80017,
  gid_used: 1,
  gid_retired: 0,
};

function mounted(cmd: string, args?: Record<string, unknown>) {
  switch (cmd) {
    case "idp_read_settings":
      return Promise.resolve({ data: args?.settings === "core" ? CORE : { enabled: false }, warnings: [] });
    case "idp_list":
      if (args?.kind === "identity")
        return Promise.resolve({ keys: ["e-1"], key_info: { "e-1": { login: "alice", uid: 80017, primary_gid: 80017, state: "active" } } });
      if (args?.kind === "environment")
        return Promise.resolve({ keys: ["prod"], key_info: { prod: { namespace: "", state: "active", roles: ["sysadmin"] } } });
      return Promise.resolve({ keys: [], key_info: {} });
    case "idp_list_entitlements":
      return Promise.resolve({ data: { entity_id: "e-1", entitlements: {} }, warnings: [] });
    case "idp_deny_feed":
      return Promise.resolve({
        data: {
          feed: btoa(JSON.stringify({ format: "bv-idp-deny-feed", format_version: 1, feed_version: 3, generated_at: 1, identities: [], revoked_serials: [] })),
          signature: "c2ln",
          algorithm: "ed25519+ml-dsa-65",
          key_id: "k1",
          feed_version: 3,
        },
        warnings: [],
      });
    case "idp_ssh_krl":
      return Promise.resolve({ data: { krl: "S1JM", krl_version: 3, generated_at: 1, revoked_serials: [] }, warnings: [] });
    case "idp_deny_feed_key":
      return Promise.resolve({ data: { algorithm: "a", key_id: "k1", ed25519: "ZWQ=", mldsa65: "bWw=" }, warnings: [] });
    case "idp_read_keys":
      return Promise.resolve({ data: { keys: [] }, warnings: [] });
    default:
      return Promise.reject(new Error(`unexpected ${cmd}`));
  }
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/identity-provider"]}>
      <ToastProvider>
        <IdentityProviderPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockInvoke.mockReset();
  useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
  useNamespaceStore.setState({ active: "", namespaces: [""], loaded: true });
});

describe("IdentityProviderPage", () => {
  it("offers to enable a missing mount instead of erroring, then loads", async () => {
    const user = userEvent.setup();
    let mountedYet = false;
    mockInvoke.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
      if (cmd === "idp_enable_mount") {
        mountedYet = true;
        return Promise.resolve(undefined);
      }
      if (!mountedYet) return Promise.reject({ message: "Router mount not found." });
      return mounted(cmd, args);
    });
    renderPage();

    expect(await screen.findByText(/identity provider not enabled/i)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /enable identity provider/i }));

    expect(mockInvoke).toHaveBeenCalledWith("idp_enable_mount", undefined);
    expect(await screen.findByRole("button", { name: "Identities" })).toBeInTheDocument();
    expect(await screen.findByText("alice")).toBeInTheDocument();
  });

  it("shows a real error (e.g. 403) as an error, not as 'not enabled'", async () => {
    mockInvoke.mockRejectedValue({ message: "HTTP 403: permission denied" });
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(/403/);
    expect(screen.queryByText(/not enabled/i)).not.toBeInTheDocument();
  });

  it("switches between the four tabs", async () => {
    const user = userEvent.setup();
    mockInvoke.mockImplementation(mounted);
    renderPage();

    expect(await screen.findByText("alice")).toBeInTheDocument();
    for (const tab of ["Identities", "Entitlements", "Providers", "Revocations"]) {
      expect(screen.getByRole("button", { name: tab })).toBeInTheDocument();
    }

    await user.click(screen.getByRole("button", { name: "Entitlements" }));
    expect(await screen.findByText(/identity × environment × roles/i)).toBeInTheDocument();
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("idp_list_entitlements", { entityId: "e-1" }));

    await user.click(screen.getByRole("button", { name: "Providers" }));
    expect(await screen.findByText(/SSH identity certificates/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "RADIUS" }));
    expect(await screen.findByText("RADIUS server")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revocations" }));
    expect(await screen.findByTestId("deny-feed-version")).toHaveTextContent("3");
    expect(screen.getByText(/not verified here/i)).toBeInTheDocument();
  });

  it("does nothing outside the root namespace", async () => {
    useNamespaceStore.setState({ active: "tenant-a", namespaces: ["", "tenant-a"], loaded: true });
    renderPage();
    expect(await screen.findByText(/managed at the root namespace/i)).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
  });
});
