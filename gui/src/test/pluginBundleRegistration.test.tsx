import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { PluginsPage } from "../routes/PluginsPage";
import { parsePluginBundle, sha256Hex } from "../lib/pluginBundle";

const binary = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const surface = new TextEncoder().encode(
  JSON.stringify({
    schema_version: 1,
    title: "Self-accounts",
    menus: [
      {
        id: "self-accounts.main",
        label: "My accounts",
        section: "secrets",
        route: "/plugin/self-accounts/accounts",
      },
    ],
    pages: [
      {
        route: "/plugin/self-accounts/accounts",
        title: "My accounts",
        components: [],
      },
    ],
  }),
);

async function surfaceBundle(signed = true) {
  const manifest = {
    name: "self-accounts",
    version: "0.1.0",
    plugin_type: "secret",
    runtime: "wasm",
    abi_version: "1.3",
    sha256: await sha256Hex(binary),
    size: binary.length,
    description: "fixture",
    ...(signed ? { signature: "signed-fixture", signing_key: "dev" } : {}),
    capabilities: {
      log_emit: true,
      audit_emit: true,
      storage_prefix: "",
      allowed_keys: [],
      allowed_hosts: [],
      caller_identity: true,
      storage_scope: "entity",
      credential_provider: {
        display_name: "Self-account",
        selection: "operator",
        protocols: ["ssh", "rdp", "web"],
        secret_kinds: ["password", "ssh-key"],
      },
    },
    surface: {
      schema_version: 1,
      sha256: await sha256Hex(surface),
      size: surface.length,
    },
  };
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const bundle = new Uint8Array(
    20 + manifestBytes.length + binary.length + surface.length,
  );
  bundle.set([0x42, 0x56, 0x50, 0x4c, 2, 0, 0, 0], 0);
  const view = new DataView(bundle.buffer);
  view.setUint32(8, manifestBytes.length, true);
  const manifestEnd = 12 + manifestBytes.length;
  bundle.set(manifestBytes, 12);
  view.setUint32(manifestEnd, binary.length, true);
  const binaryEnd = manifestEnd + 4 + binary.length;
  bundle.set(binary, manifestEnd + 4);
  view.setUint32(binaryEnd, surface.length, true);
  bundle.set(surface, binaryEnd + 4);
  return bundle;
}

beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((command: string) => {
    switch (command) {
      case "plugins_list":
        return Promise.resolve({ plugins: [] });
      case "plugins_get_accept_unsigned":
        return Promise.resolve(false);
      case "plugins_get_publishers":
        return Promise.resolve({ dev: "publisher-key" });
      case "plugins_register":
        return Promise.resolve({});
      default:
        return Promise.resolve(null);
    }
  });
});

describe("surface-bearing plugin bundles", () => {
  it("forwards the authenticated surface through the normal Register dialog", async () => {
    const bundle = await surfaceBundle();
    const { container } = render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await userEvent.click(
      await screen.findByRole("button", { name: "+ Register plugin" }),
    );
    const input = container.querySelector<HTMLInputElement>('input[type="file"]');
    expect(input).not.toBeNull();
    const file = {
      name: "bastion-plugin-self-accounts.bvplugin",
      arrayBuffer: () => Promise.resolve(bundle.buffer.slice(0)),
    };
    fireEvent.change(input!, { target: { files: [file] } });

    await screen.findByText(/manifest auto-filled from bundle/);
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find(([command]) => command === "plugins_register");
      expect(call).toBeDefined();
      expect(call![1].input.manifest.surface).toEqual({
        schema_version: 1,
        sha256: expect.any(String),
        size: surface.length,
      });
      expect(call![1].input.surface_b64).toBe(btoa(String.fromCharCode(...surface)));
    });
  });

  it("refuses a surface whose bytes do not match the signed manifest reference", async () => {
    const bundle = await surfaceBundle();
    bundle[bundle.length - 1] ^= 0x01;
    await expect(parsePluginBundle(bundle)).rejects.toThrow(
      /does not match the embedded surface/,
    );
  });

  it("preserves an unsigned bundle's complete provider manifest", async () => {
    const bundle = await surfaceBundle(false);
    const { container } = render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await userEvent.click(
      await screen.findByRole("button", { name: "+ Register plugin" }),
    );
    const input = container.querySelector<HTMLInputElement>('input[type="file"]');
    fireEvent.change(input!, {
      target: {
        files: [
          {
            name: "unsigned-self-accounts.bvplugin",
            arrayBuffer: () => Promise.resolve(bundle.buffer.slice(0)),
          },
        ],
      },
    });
    await screen.findByText(/manifest auto-filled from bundle/);
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => {
      const call = mockInvoke.mock.calls.find(([command]) => command === "plugins_register");
      expect(call![1].input.manifest.capabilities).toMatchObject({
        caller_identity: true,
        storage_scope: "entity",
        credential_provider: { display_name: "Self-account" },
      });
      expect(call![1].input.manifest.surface).toBeDefined();
      expect(call![1].input.surface_b64).toBeTruthy();
    });
  });

  it("keeps the newest selection when an older file read finishes later", async () => {
    let finishFirst!: (buffer: ArrayBuffer) => void;
    const firstRead = new Promise<ArrayBuffer>((resolve) => {
      finishFirst = resolve;
    });
    const { container } = render(
      <MemoryRouter>
        <PluginsPage />
      </MemoryRouter>,
    );
    await userEvent.click(
      await screen.findByRole("button", { name: "+ Register plugin" }),
    );
    const input = container.querySelector<HTMLInputElement>('input[type="file"]')!;
    fireEvent.change(input, {
      target: { files: [{ name: "first.wasm", arrayBuffer: () => firstRead }] },
    });
    fireEvent.change(input, {
      target: {
        files: [
          {
            name: "second.wasm",
            arrayBuffer: () => Promise.resolve(new Uint8Array([2]).buffer),
          },
        ],
      },
    });
    await screen.findByText("second.wasm");
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Register" })).toBeEnabled(),
    );

    await act(async () => finishFirst(new Uint8Array([1]).buffer));
    expect(screen.getByText("second.wasm")).toBeInTheDocument();
  });
});
