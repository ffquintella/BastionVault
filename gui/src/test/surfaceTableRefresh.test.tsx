import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

const bundle: ActiveSurfaceBundle = {
  etag: "surface-etag",
  entries: [
    {
      plugin: "self-accounts",
      version: "0.1.1",
      mount: "self-accounts/",
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
                row_actions: [
                  {
                    label: "Delete",
                    binding: { op: "delete", path: "{mount}/v2/accounts/{id}" },
                  },
                ],
                empty_text: "You have no accounts yet.",
              },
              {
                kind: "form",
                id: "add-account",
                schema: {
                  type: "object",
                  properties: { label: { type: "string", title: "Label" } },
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

let accounts: Record<string, unknown>[] = [];

function dispatchCalls(op: string) {
  return mockInvoke.mock.calls.filter(
    ([command, payload]) =>
      command === "plugin_surface_dispatch" &&
      (payload as { args: { op: string } }).args.op === op,
  );
}

beforeEach(() => {
  accounts = [];
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((command: string, payload?: unknown) => {
    if (command === "plugin_surface_dispatch") {
      const { op, params } = (payload as {
        args: { op: string; params: Record<string, string> };
      }).args;
      if (op === "list") return Promise.resolve({ data: { keys: accounts.map((a) => ({ ...a })) } });
      if (op === "write") {
        accounts.push({ id: "acct-1", label: "Corp admin" });
        return Promise.resolve({ data: { id: "acct-1" } });
      }
      if (op === "delete") {
        accounts = accounts.filter((a) => a.id !== params.id);
        return Promise.resolve({ data: null });
      }
    }
    if (command === "plugin_surfaces_refresh") return Promise.resolve({ bundle });
    return Promise.resolve({});
  });
  usePluginSurfacesStore.setState({ bundle, loading: false, error: null });
});

afterEach(() => {
  usePluginSurfacesStore.getState().clear();
});

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/plugin/self-accounts/accounts?pluginWindow=self-accounts-test"]}>
      <SurfaceRouter />
    </MemoryRouter>,
  );
}

describe("plugin surface table refresh", () => {
  it("shows a record added by a form on the same page without navigating away", async () => {
    renderPage();
    expect(await screen.findByText("You have no accounts yet.")).toBeInTheDocument();
    expect(dispatchCalls("list")).toHaveLength(1);

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "Corp admin" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    });

    expect(await screen.findByText("Corp admin")).toBeInTheDocument();
    expect(dispatchCalls("write")).toHaveLength(1);
    expect(dispatchCalls("list")).toHaveLength(2);
  });

  it("re-lists once after a row action", async () => {
    accounts = [{ id: "acct-1", label: "Corp admin" }];
    renderPage();
    expect(await screen.findByText("Corp admin")).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    });

    expect(await screen.findByText("You have no accounts yet.")).toBeInTheDocument();
    await waitFor(() => expect(dispatchCalls("list")).toHaveLength(2));
  });
});
