import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { SurfaceRouter } from "../components/surface/SurfaceRouter";
import type { ActiveSurfaceBundle } from "../lib/api";
import { usePluginSurfacesStore } from "../stores/pluginSurfacesStore";

function selfAccountsBundle(mount: string): ActiveSurfaceBundle {
  return {
    etag: "surface-etag",
    entries: [
      {
        plugin: "self-accounts",
        version: "0.1.1",
        mount,
        assets: [],
        surface: {
          schema_version: 1,
          title: "Self-accounts",
          pages: [
            {
              route: "/plugin/self-accounts/accounts",
              title: "My accounts",
              components: [
                {
                  kind: "table",
                  id: "accounts",
                  binding: { op: "list", path: "{mount}/v2/accounts" },
                  columns: [{ field: "label", label: "Label" }],
                },
                {
                  kind: "form",
                  id: "add-account",
                  schema: {
                    type: "object",
                    properties: {
                      resource_types: {
                        type: "array",
                        title: "Resource types",
                        "x-bv-options": "resource-types",
                      },
                    },
                  },
                  submit: {
                    label: "Add account",
                    binding: { op: "write", path: "{mount}/v2/accounts" },
                  },
                },
              ],
            },
          ],
        },
      },
    ],
  };
}

function renderSelfAccounts(bundle = selfAccountsBundle("self-accounts/")) {
  usePluginSurfacesStore.setState({
    bundle,
    loading: false,
    error: null,
  });
  return render(
    <MemoryRouter
      initialEntries={[
        "/plugin/self-accounts/accounts?pluginWindow=self-accounts-test",
      ]}
    >
      <SurfaceRouter />
    </MemoryRouter>,
  );
}

function callsFor(command: string) {
  return mockInvoke.mock.calls.filter(([called]) => called === command);
}

beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((command: string) => {
    if (command === "plugin_surface_dispatch") {
      return Promise.reject(new Error("404 not found"));
    }
    if (command === "resource_types_read") {
      return Promise.reject(new Error("resource types unavailable"));
    }
    return Promise.resolve({});
  });
});

afterEach(() => {
  usePluginSurfacesStore.getState().clear();
});

describe("plugin surface runtime failures", () => {
  it("keeps a failed binding stable across surface watcher errors", async () => {
    renderSelfAccounts();

    expect(await screen.findByText("404 not found")).toBeInTheDocument();
    expect(await screen.findByLabelText("server")).toBeInTheDocument();
    expect(callsFor("plugin_surface_dispatch")).toEqual([
      [
        "plugin_surface_dispatch",
        {
          args: {
            op: "list",
            path: "{mount}/v2/accounts",
            mount: "self-accounts/",
            params: {},
            body: null,
          },
        },
      ],
    ]);
    expect(callsFor("resource_types_read")).toHaveLength(1);

    await act(async () => {
      usePluginSurfacesStore.setState({ error: "watch failed once" });
      usePluginSurfacesStore.setState({ error: "watch failed twice" });
      await Promise.resolve();
    });

    await waitFor(() => expect(screen.getByText("404 not found")).toBeInTheDocument());
    expect(callsFor("plugin_surface_dispatch")).toHaveLength(1);
    expect(callsFor("resource_types_read")).toHaveLength(1);
  });

  it("does not dispatch bindings until the plugin is mounted", async () => {
    renderSelfAccounts(selfAccountsBundle(""));

    expect(
      await screen.findByText(/is not mounted in the active namespace/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Admin.*Mounts.*Mount Engine/i)).toBeInTheDocument();
    expect(callsFor("plugin_surface_dispatch")).toHaveLength(0);
    expect(callsFor("resource_types_read")).toHaveLength(0);
  });

  it("does not let a delayed refresh from the previous namespace overwrite the current bundle", async () => {
    let resolvePrevious!: (value: { bundle: ActiveSurfaceBundle }) => void;
    let resolveCurrent!: (value: { bundle: ActiveSurfaceBundle }) => void;
    const previous = new Promise<{ bundle: ActiveSurfaceBundle }>((resolve) => {
      resolvePrevious = resolve;
    });
    const current = new Promise<{ bundle: ActiveSurfaceBundle }>((resolve) => {
      resolveCurrent = resolve;
    });
    let refreshCall = 0;
    mockInvoke.mockImplementation((command: string) => {
      if (command !== "plugin_surfaces_refresh") return Promise.resolve({});
      refreshCall += 1;
      return refreshCall === 1 ? previous : current;
    });

    const previousRefresh = usePluginSurfacesStore.getState().refresh();
    const currentRefresh = usePluginSurfacesStore.getState().refresh();
    const currentBundle = selfAccountsBundle("current-accounts/");
    currentBundle.etag = "current-etag";
    const previousBundle = selfAccountsBundle("previous-accounts/");
    previousBundle.etag = "previous-etag";

    await act(async () => {
      resolveCurrent({ bundle: currentBundle });
      await currentRefresh;
      resolvePrevious({ bundle: previousBundle });
      await previousRefresh;
    });

    expect(usePluginSurfacesStore.getState().bundle?.etag).toBe("current-etag");
    expect(usePluginSurfacesStore.getState().bundle?.entries[0].mount).toBe("current-accounts/");
    expect(usePluginSurfacesStore.getState().error).toBeNull();
  });
});
