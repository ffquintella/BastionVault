/**
 * Secrets page: the owner badge and the Share panel name the secret by its own
 * `<mount>/<name>` (T508). The server keys a KV secret's owner and shares on
 * that name verbatim (T499), so a secret named `data/x` must never be sent as
 * `x`: an administrator sharing `data/x` would have granted a share on `x`.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useNamespaceStore } from "../stores/namespaceStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { SecretsPage } from "../routes/SecretsPage";

/** `tree` maps a listed path (mount prefix included) to its keys. */
function mockVault(tree: Record<string, string[]>) {
  mockInvoke.mockImplementation((cmd: string, args?: { path?: string }) => {
    switch (cmd) {
      case "list_mounts":
        return Promise.resolve([{ path: "secret/", mount_type: "kv-v2", description: "" }]);
      case "list_secrets":
        return Promise.resolve({ keys: tree[args?.path ?? ""] ?? [] });
      case "read_secret":
        return Promise.resolve({ data: { field: "placeholder" }, available_envs: [] });
      case "read_kv_v2_engine_config":
        return Promise.resolve({ environments: [] });
      case "get_kv_owner":
        return Promise.resolve({ owned: false });
      case "list_shares_for_target":
        return Promise.resolve([]);
      case "list_asset_groups":
        return Promise.resolve({ groups: [] });
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

/** The argument `field` of every `cmd` call so far. */
function sent(cmd: string, field: string): string[] {
  return mockInvoke.mock.calls
    .filter((c) => c[0] === cmd)
    .map((c) => (c[1] as Record<string, string>)[field]);
}

/** Click through `folders`, select the leaf `key` and open its Share panel. */
async function share(folders: string[], key: string) {
  for (const f of folders) await userEvent.click(await screen.findByText(f));
  await userEvent.click(await screen.findByText(key));
  await userEvent.click(await screen.findByRole("button", { name: "Share" }));
}

beforeEach(() => {
  mockInvoke.mockReset();
  useNamespaceStore.setState({ namespaces: [""], active: "", loaded: true });
});

describe("Secrets page: owner and shares by the secret's own name", () => {
  it("asks for the owner of data/x and shares data/x, never x", async () => {
    mockVault({ "secret/": ["data/"], "secret/data/": ["x"] });
    renderPage();
    await share(["data/"], "x");

    await waitFor(() => expect(sent("list_shares_for_target", "targetPath")).toContain("secret/data/x"));
    expect(sent("get_kv_owner", "path")).toContain("secret/data/x");
    expect(sent("get_kv_owner", "path")).not.toContain("secret/x");
    expect(sent("list_shares_for_target", "targetPath")).not.toContain("secret/x");
    expect(screen.getAllByText("secret/data/x").length).toBeGreaterThan(0);
  });

  it("keeps a plain secret's name as it was", async () => {
    mockVault({ "secret/": ["x"] });
    renderPage();
    await share([], "x");

    await waitFor(() => expect(sent("list_shares_for_target", "targetPath")).toEqual(["secret/x"]));
    expect(new Set(sent("get_kv_owner", "path"))).toEqual(new Set(["secret/x"]));
  });

  it("names a nested secret under a metadata/ folder by its full name", async () => {
    mockVault({ "secret/": ["metadata/"], "secret/metadata/": ["team/"], "secret/metadata/team/": ["db"] });
    renderPage();
    await share(["metadata/", "team/"], "db");

    await waitFor(() => expect(sent("list_shares_for_target", "targetPath")).toContain("secret/metadata/team/db"));
    expect(sent("get_kv_owner", "path")).not.toContain("secret/team/db");
  });
});
