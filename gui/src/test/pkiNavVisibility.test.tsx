/**
 * The PKI sidebar entry follows the server's ACL-filtered mount list, not
 * just a policy *name*.
 *
 * `esi-pki-issue` (an operator-authored policy) grants the `pki/` paths but is
 * not one of the seeded names the nav used to require, so the menu stayed
 * hidden for a user who could in fact issue certificates. The mount list from
 * `sys/internal/ui/mounts` only contains a mount the token's ACL reaches, so a
 * listed `pki` mount is enough; a failed lookup must never widen the nav.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { Layout } from "../components/Layout";
import { useAuthStore } from "../stores/authStore";
import type { MountInfo } from "../lib/types";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const mockListMounts = vi.fn<() => Promise<MountInfo[]>>();
vi.mock("../lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/api")>()),
  listMounts: () => mockListMounts(),
  listPluginSurfaces: () => Promise.resolve({ surfaces: [] }),
  listNotifications: () => Promise.resolve({ notifications: [] }),
  namespacesSelf: () =>
    Promise.resolve({ namespaces: [], token_namespace: "", root: false }),
  getActiveNamespace: () => Promise.resolve({ namespace: "" }),
  logout: () => Promise.resolve(),
}));

const pkiMount: MountInfo = { path: "pki/", mount_type: "pki", description: "" };

function renderNav(policies: string[]) {
  useAuthStore.setState({ token: "test-token", policies, isAuthenticated: true });
  render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <ToastProvider>
        <Layout>
          <div>page body</div>
        </Layout>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("PKI nav visibility", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
    mockListMounts.mockReset();
    useAuthStore.setState({ token: "", policies: [], isAuthenticated: false });
  });

  it("shows PKI for a custom-named policy when the server lists the pki mount", async () => {
    mockListMounts.mockResolvedValue([pkiMount]);
    renderNav(["esi-pki-issue", "default"]);
    expect(await screen.findByRole("link", { name: "PKI" })).toBeInTheDocument();
  });

  it("hides PKI when the server does not list a pki mount", async () => {
    mockListMounts.mockResolvedValue([]);
    renderNav(["esi-pki-issue", "default"]);
    await waitFor(() => expect(mockListMounts).toHaveBeenCalled());
    await screen.findByText("page body");
    expect(screen.queryByRole("link", { name: "PKI" })).not.toBeInTheDocument();
  });

  it("does not widen the nav when the mount lookup fails", async () => {
    mockListMounts.mockRejectedValue(new Error("403"));
    renderNav(["esi-pki-issue", "default"]);
    await waitFor(() => expect(mockListMounts).toHaveBeenCalled());
    await screen.findByText("page body");
    expect(screen.queryByRole("link", { name: "PKI" })).not.toBeInTheDocument();
  });

  it("still honours the seeded policy names when the lookup fails", async () => {
    mockListMounts.mockRejectedValue(new Error("403"));
    renderNav(["pki-user", "default"]);
    expect(await screen.findByRole("link", { name: "PKI" })).toBeInTheDocument();
  });
});
