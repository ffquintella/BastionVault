import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

// Tauri bridge stub. The list reads the type config + the search page, then
// the connect-access validator probes capabilities and (for a connect-only
// caller) the effective transport policy.
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

const RESOURCE = "web01";

/** One SSH profile whose credential is a stored secret — launchable for a
 *  caller who can read it, and for a connect-only caller only when the
 *  session is brokered through a bastion. */
const HINTS = [{ protocol: "ssh", credential_source: { kind: "secret" } }];

function mockVault({
  connectOnly,
  transport,
}: {
  connectOnly: boolean;
  transport: string;
}) {
  mockInvoke.mockImplementation((cmd: string, args: any) => {
    switch (cmd) {
      case "resource_types_read":
        return Promise.resolve(null);
      case "list_asset_groups":
        return Promise.resolve({ groups: [] });
      case "asset_groups_for_resource":
        return Promise.resolve({ groups: [] });
      case "search_resources":
        return Promise.resolve({
          items: [
            {
              name: RESOURCE,
              type: "server",
              hostname: "web01.example.test",
              connect_profiles: HINTS,
            },
          ],
          total: 1,
          has_more: false,
        });
      case "capabilities_self":
        return Promise.resolve({
          paths: Object.fromEntries(
            (args.paths as string[]).map((p) => [
              p,
              connectOnly ? ["connect"] : ["read"],
            ]),
          ),
        });
      case "rustion_policy_effective":
        return Promise.resolve({ transport, bastions: [] });
      default:
        return Promise.reject(new Error(`unmocked: ${cmd}`));
    }
  });
}

async function renderResources() {
  const { ResourcesPage } = await import("../routes/ResourcesPage");
  render(
    <MemoryRouter>
      <ToastProvider>
        <ResourcesPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await screen.findByText(RESOURCE);
}

function connectChip() {
  return screen.getAllByText("Connect")[0];
}

describe("resource card Connect gate", () => {
  beforeEach(async () => {
    mockInvoke.mockReset();
    const { clearConnectAccessCache } = await import("../lib/connectValidation");
    clearConnectAccessCache();
    useAuthStore.setState({
      token: "t",
      isAuthenticated: true,
      // Not an admin: the validator's probes are what decide the gate.
      policies: ["resource-user"],
      entityId: "entity-1",
    });
  });

  it("leaves Connect live for a caller who can read the credential", async () => {
    mockVault({ connectOnly: false, transport: "direct" });
    await renderResources();
    await waitFor(() =>
      expect(connectChip()).toHaveAttribute("role", "button"),
    );
    expect(connectChip()).not.toHaveAttribute("aria-disabled");
  });

  it("disables Connect for a connect-only caller with a direct-only profile", async () => {
    mockVault({ connectOnly: true, transport: "direct" });
    await renderResources();
    // The chip starts live (nothing proven yet) and goes inert once the
    // validator resolves both inputs.
    await waitFor(() =>
      expect(connectChip()).toHaveAttribute("aria-disabled", "true"),
    );
    expect(connectChip().getAttribute("title")).toMatch(/bastion/);
  });

  it("keeps Connect live for a connect-only caller when the tier brokers the session", async () => {
    // The profile isn't tagged `kind: "rustion"`, but the resource is pinned
    // to rustion-required, so the credential resolves server-side and the
    // session is launchable. Greying this out is the regression this gate
    // must not reintroduce.
    mockVault({ connectOnly: true, transport: "rustion-required" });
    await renderResources();
    await waitFor(() =>
      expect(
        mockInvoke.mock.calls.some((c) => c[0] === "rustion_policy_effective"),
      ).toBe(true),
    );
    expect(connectChip()).not.toHaveAttribute("aria-disabled");
  });

  it("disables Connect on a resource with no connection profile", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "resource_types_read":
          return Promise.resolve(null);
        case "list_asset_groups":
          return Promise.resolve({ groups: [] });
        case "search_resources":
          return Promise.resolve({
            items: [{ name: RESOURCE, type: "server", connect_profiles: [] }],
            total: 1,
            has_more: false,
          });
        case "capabilities_self":
          return Promise.resolve({ paths: {} });
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
    await renderResources();
    expect(connectChip()).toHaveAttribute("aria-disabled", "true");
    expect(connectChip().getAttribute("title")).toMatch(
      /No connection profile/,
    );
  });

  it("re-probes after a forced revalidation from the app menu", async () => {
    mockVault({ connectOnly: true, transport: "direct" });
    await renderResources();
    await waitFor(() =>
      expect(connectChip()).toHaveAttribute("aria-disabled", "true"),
    );

    // The operator has since been granted read on the credential. Without the
    // menu item the card would hold the stale verdict for the whole TTL.
    mockVault({ connectOnly: false, transport: "direct" });
    const { revalidateConnectAccess } = await import(
      "../lib/connectValidation"
    );
    revalidateConnectAccess();
    await waitFor(() =>
      expect(connectChip()).not.toHaveAttribute("aria-disabled"),
    );
  });
});
