/**
 * Secrets page: the asset-group chips and filters look a secret up by its own
 * `<mount>/<name>` (T507). The server keys a group's KV-secret members on that
 * name, so a secret named `data/x` must show its own groups, never `x`'s.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useNamespaceStore } from "../stores/namespaceStore";
import { resetAssetGroupCacheForTests } from "../lib/assetGroupCache";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { SecretsPage } from "../routes/SecretsPage";

/** `tree` maps a listed path to its keys; `bySecret` is the server's map. */
function mockVault(tree: Record<string, string[]>, bySecret: Record<string, string[]>) {
  mockInvoke.mockImplementation((cmd: string, args?: { path?: string }) => {
    switch (cmd) {
      case "list_mounts":
        return Promise.resolve([{ path: "secret/", mount_type: "kv-v2", description: "" }]);
      case "list_secrets":
        return Promise.resolve({ keys: tree[args?.path ?? ""] ?? [] });
      case "get_kv_owner":
        return Promise.resolve({ owned: false });
      case "asset_groups_batch":
        return Promise.resolve({
          unchanged: false,
          version: "v1",
          shape: "slim",
          namespace: "",
          groups: [],
          names: [...new Set(Object.values(bySecret).flat())].sort(),
          by_resource: {},
          by_secret: bySecret,
          by_file: {},
          warnings: [],
        });
      default:
        return Promise.resolve(null);
    }
  });
}

function renderPage() {
  render(
    <MemoryRouter>
      <ToastProvider>
        <SecretsPage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

/** The group chips shown under the key list entry `key`. */
function chips(key: string): string[] {
  const entry = screen.getByText(key, { selector: "span.truncate" }).closest("div.space-y-0\\.5 > div");
  if (!entry) return [];
  return within(entry as HTMLElement)
    .queryAllByTitle(/^Member of asset group/)
    .map((c) => c.textContent ?? "");
}

beforeEach(() => {
  mockInvoke.mockReset();
  resetAssetGroupCacheForTests();
  useNamespaceStore.setState({ namespaces: [""], active: "", loaded: true });
});

describe("Secrets page: asset-group chips by the secret's own name", () => {
  it("shows data/x's own groups, never x's", async () => {
    mockVault(
      { "secret/": ["data/", "x"], "secret/data/": ["x"] },
      { "secret/x": ["gx"], "secret/data/x": ["gd"] },
    );
    renderPage();
    await waitFor(() => expect(chips("x")).toEqual(["gx"]));

    await userEvent.click(await screen.findByText("data/"));
    await waitFor(() => expect(screen.getByText("x", { selector: "span.truncate" })).toBeTruthy());
    await waitFor(() => expect(chips("x")).toEqual(["gd"]));
  });

  it("keeps data/x in the list when filtering by its own group", async () => {
    mockVault(
      { "secret/": ["data/", "x"], "secret/data/": ["x"] },
      { "secret/data/x": ["gd"] },
    );
    renderPage();
    await userEvent.click(await screen.findByText("data/"));
    await userEvent.click(await screen.findByRole("button", { name: /gd/ }));
    await waitFor(() => expect(chips("x")).toEqual(["gd"]));
    expect(screen.queryByText("No secrets in this group")).toBeNull();
  });
});
