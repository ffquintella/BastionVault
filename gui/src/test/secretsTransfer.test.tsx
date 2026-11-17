/**
 * Secrets page: the "Copy / Move to namespace" action for one KV secret
 * (T496, features/cross-namespace-copy-move.md). The transfer must carry the
 * secret's own name under its real mount, never a stripped or re-derived one.
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

const BUTTON = "Copy / Move to namespace";

type Tree = Record<string, string[]>;

const PLAN = {
  transferred: { secrets: 1, versions: 3, history: 0, shares: 0 },
  warnings: [
    { code: "deleted-version-not-recoverable", subject: "v2", message: "version 2 arrives destroyed" },
    { code: "kv-environment-overrides-normalized", subject: "x", message: "an override equal to its base is dropped" },
  ],
  dry_run: true,
  destination: { namespace: "team-b", mount: "secret", path: "x" },
};

/** `tree` maps a listed path (mount prefix included) to its keys. */
function mockVault(mounts: { path: string; mount_type: string }[], tree: Tree) {
  mockInvoke.mockImplementation((cmd: string, args?: { path?: string; dryRun?: boolean }) => {
    switch (cmd) {
      case "list_mounts":
        return Promise.resolve(mounts.map((m) => ({ ...m, description: "" })));
      case "list_secrets":
        return Promise.resolve({ keys: tree[args?.path ?? ""] ?? [] });
      case "read_secret":
        return Promise.resolve({ data: { field: "placeholder" }, available_envs: [] });
      case "read_kv_v2_engine_config":
        return Promise.resolve({ environments: [] });
      case "get_kv_owner":
        return Promise.resolve({ owned: false });
      case "list_asset_groups":
        return Promise.resolve({ groups: [] });
      case "transfer_object":
        return Promise.resolve(args?.dryRun ? PLAN : { ...PLAN, dry_run: false });
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

/** Click through `folders` (as listed) and select the leaf `key`. */
async function select(folders: string[], key: string) {
  for (const f of folders) await userEvent.click(await screen.findByText(f));
  await userEvent.click(await screen.findByText(key));
  return screen.findByRole("button", { name: BUTTON });
}

function transferCalls() {
  return mockInvoke.mock.calls.filter((c) => c[0] === "transfer_object").map((c) => c[1]);
}

beforeEach(() => {
  mockInvoke.mockReset();
  useNamespaceStore.setState({ namespaces: ["", "team-a", "team-b"], active: "", loaded: true });
});

describe("Secrets page: transfer a KV secret", () => {
  it("opens the shared dialog for the selected secret and sends kind kv-secret", async () => {
    mockVault([{ path: "secret/", mount_type: "kv-v2" }], { "secret/": ["app"] });
    renderPage();
    await userEvent.click(await select([], "app"));

    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("Copy or move to another namespace");
    expect(screen.getByLabelText("Destination mount")).toHaveValue("secret");
    expect(screen.getByLabelText("Destination path")).toHaveValue("app");

    await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "team-b");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    // The KV-specific warnings are listed with the others.
    await screen.findByText("deleted-version-not-recoverable");
    expect(screen.getByText("kv-environment-overrides-normalized")).toBeInTheDocument();
    expect(transferCalls()).toEqual([
      {
        op: "copy",
        kind: "kv-secret",
        source: { namespace: "", mount: "secret", path: "app" },
        destination: { namespace: "team-b", mount: "secret", path: "app" },
        onConflict: "refuse",
        dryRun: true,
      },
    ]);

    await userEvent.click(await screen.findByRole("button", { name: "Copy now" }));
    await screen.findByText(/Transfer complete/);
    const calls = transferCalls() as { kind: string; dryRun: boolean }[];
    expect(calls).toHaveLength(2);
    expect(calls[1].kind).toBe("kv-secret");
    expect(calls[1].dryRun).toBe(false);
  });

  it("sends a slash-named mount and a nested secret path as the server expects them", async () => {
    mockVault([{ path: "team/kv/", mount_type: "kv-v2" }], {
      "team/kv/": ["a/"],
      "team/kv/a/": ["b/"],
      "team/kv/a/b/": ["c"],
    });
    useNamespaceStore.setState({ namespaces: ["", "team-a", "team-b"], active: "team-a", loaded: true });
    renderPage();
    await userEvent.click(await select(["a/", "b/"], "c"));
    await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "team-b");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await screen.findByText("deleted-version-not-recoverable");
    expect(transferCalls()[0]).toMatchObject({
      kind: "kv-secret",
      source: { namespace: "team-a", mount: "team/kv", path: "a/b/c" },
      destination: { namespace: "team-b", mount: "team/kv", path: "a/b/c" },
    });
  });

  it("never strips a secret's own name that starts with data/ (T508 stays out of the transfer)", async () => {
    mockVault([{ path: "secret/", mount_type: "kv-v2" }], {
      "secret/": ["data/"],
      "secret/data/": ["x"],
    });
    renderPage();
    await userEvent.click(await select(["data/"], "x"));
    await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "team-b");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await screen.findByText("deleted-version-not-recoverable");
    expect(transferCalls()[0]).toMatchObject({
      kind: "kv-secret",
      source: { namespace: "", mount: "secret", path: "data/x" },
      destination: { namespace: "team-b", mount: "secret", path: "data/x" },
    });
    // Neither the mount nor the path was re-derived from the ACL form.
    const sent = transferCalls()[0] as { source: { path: string } };
    expect(sent.source.path).not.toBe("x");
  });

  it("refreshes the list after a move and drops the moved secret on close", async () => {
    mockVault([{ path: "secret/", mount_type: "kv-v2" }], { "secret/": ["app"] });
    renderPage();
    await userEvent.click(await select([], "app"));
    await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "team-b");
    await userEvent.click(screen.getByRole("radio", { name: "Move" }));
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await userEvent.click(await screen.findByRole("checkbox", { name: /source will be deleted/i }));
    const listsBefore = mockInvoke.mock.calls.filter((c) => c[0] === "list_secrets").length;
    await userEvent.click(screen.getByRole("button", { name: "Move now" }));
    await screen.findByText(/Transfer complete/);
    await waitFor(() =>
      expect(mockInvoke.mock.calls.filter((c) => c[0] === "list_secrets").length).toBeGreaterThan(listsBefore),
    );
    await userEvent.click(screen.getByText("Close"));
    expect(await screen.findByText("No secret selected")).toBeInTheDocument();
  });

  it("sends nothing and offers no transfer once the page leaves the mount's own path", async () => {
    mockVault([{ path: "team/kv/", mount_type: "kv-v2" }], {
      "team/kv/": ["a/"],
      "team/kv/a/": ["c"],
    });
    renderPage();
    const button = await select(["a/"], "c");
    // The action row wraps instead of overflowing the detail card.
    expect(button.parentElement).toHaveClass("flex-wrap");
    // A breadcrumb above the mount's own path.
    await userEvent.click(screen.getByText("team"));
    await waitFor(() => expect(screen.queryByRole("button", { name: BUTTON })).not.toBeInTheDocument());
    expect(transferCalls()).toEqual([]);
  });

  it("keeps the secret selected after a copy", async () => {
    mockVault([{ path: "secret/", mount_type: "kv-v2" }], { "secret/": ["app"] });
    renderPage();
    await userEvent.click(await select([], "app"));
    await userEvent.selectOptions(screen.getByLabelText("Destination namespace"), "team-b");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await userEvent.click(await screen.findByRole("button", { name: "Copy now" }));
    await screen.findByText(/Transfer complete/);
    await userEvent.click(screen.getByText("Close"));
    expect(screen.queryByText("No secret selected")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: BUTTON })).toBeInTheDocument();
  });

  it("is disabled with a reason when no other namespace is available", async () => {
    useNamespaceStore.setState({ namespaces: [""], active: "", loaded: true });
    mockVault([{ path: "secret/", mount_type: "kv-v2" }], { "secret/": ["app"] });
    renderPage();
    const button = await select([], "app");
    expect(button).toBeDisabled();
    expect(button.getAttribute("title")).toMatch(/No other namespace/);
  });

  it("is disabled with a reason on a KV v1 mount, which the transfer does not carry", async () => {
    mockVault([{ path: "kv1/", mount_type: "kv" }], { "kv1/": ["app"] });
    renderPage();
    const button = await select([], "app");
    expect(button).toBeDisabled();
    expect(button.getAttribute("title")).toMatch(/KV v2/);
    expect(transferCalls()).toEqual([]);
  });
});
