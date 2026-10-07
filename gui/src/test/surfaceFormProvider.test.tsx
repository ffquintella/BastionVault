/**
 * Plugin surface forms: the generic keywords the self-accounts management UI
 * needs — multi-select (`type: "array"` + `items.enum`), masked multi-line
 * secrets (`format: "secret-textarea"`) and host-supplied option lists
 * (`x-bv-options`).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { SurfaceForm } from "../components/surface/SurfaceForm";
import { DEFAULT_RESOURCE_TYPES } from "../lib/resourceTypes";
import type { ActiveSurfaceEntry, SurfaceForm as FormSpec } from "../lib/api";

const ENTRY = {
  plugin: "self-accounts",
  version: "1.0.0",
  mount: "self-accounts/",
  surface: {},
  assets: [],
} as unknown as ActiveSurfaceEntry;

function spec(properties: Record<string, unknown>, required: string[] = []): FormSpec {
  return {
    kind: "form",
    id: "f",
    schema: { type: "object", properties, required },
    submit: { label: "Save", binding: { op: "write", path: "{mount}/v2/accounts" } },
  } as unknown as FormSpec;
}

function dispatched(): Record<string, unknown> | undefined {
  const call = mockInvoke.mock.calls.find((c) => c[0] === "plugin_surface_dispatch");
  const args = call?.[1] as { args?: { body?: Record<string, unknown> } } | undefined;
  return args?.args?.body ?? (call?.[1] as Record<string, unknown> | undefined);
}

beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "resource_types_read") {
      return Promise.resolve({
        server: DEFAULT_RESOURCE_TYPES.server,
        custom_db: { id: "custom_db", label: "Custom DB", color: "info", fields: [] },
      });
    }
    if (cmd === "plugin_surfaces_refresh") return Promise.resolve({ bundle: { entries: [] } });
    return Promise.resolve({});
  });
});

describe("SurfaceForm — multi-select", () => {
  it("renders items.enum as checkboxes and submits the chosen values", async () => {
    const user = userEvent.setup();
    render(
      <SurfaceForm
        entry={ENTRY}
        spec={spec({ protocols: { type: "array", title: "Protocols", items: { enum: ["ssh", "rdp", "web"] } } })}
      />,
    );
    await user.click(screen.getByLabelText("ssh"));
    await user.click(screen.getByLabelText("web"));
    await user.click(screen.getByLabelText("ssh")); // untick
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(JSON.stringify(dispatched())).toContain('"protocols":["web"]'));
  });
});

describe("SurfaceForm — host-supplied options", () => {
  it("fills resource types from the Resources page's configuration", async () => {
    render(
      <SurfaceForm
        entry={ENTRY}
        spec={spec({ resource_types: { type: "array", title: "Types", "x-bv-options": "resource-types" } })}
      />,
    );
    expect(await screen.findByLabelText("custom_db")).toBeInTheDocument();
    expect(screen.getByLabelText("server")).toBeInTheDocument();
  });

  it("offers the OS families without an unset entry", async () => {
    render(
      <SurfaceForm
        entry={ENTRY}
        spec={spec({ os_types: { type: "array", title: "OS", "x-bv-options": "os-types" } })}
      />,
    );
    expect(await screen.findByLabelText("windows")).toBeInTheDocument();
    expect(screen.getByLabelText("linux")).toBeInTheDocument();
    expect(screen.queryByLabelText("")).toBeNull();
  });

  it("ignores an unknown x-bv-options kind rather than guessing", async () => {
    render(
      <SurfaceForm
        entry={ENTRY}
        spec={spec({ x: { type: "array", title: "X", "x-bv-options": "secrets" } })}
      />,
    );
    expect(await screen.findByText("No options available.")).toBeInTheDocument();
  });
});

describe("SurfaceForm — secret-textarea", () => {
  it("masks the input, disables browser help, and clears it after a save", async () => {
    const user = userEvent.setup();
    render(
      <SurfaceForm
        entry={ENTRY}
        spec={spec({ private_key: { type: "string", title: "Private key", format: "secret-textarea" } })}
      />,
    );
    const box = screen.getByLabelText("Private key") as HTMLTextAreaElement;
    expect(box.getAttribute("autocomplete")).toBe("off");
    expect(box.getAttribute("spellcheck")).toBe("false");
    expect(box.getAttribute("data-masked")).toBe("true");

    await user.type(box, "KEY-MATERIAL");
    expect(box.value).toBe("KEY-MATERIAL");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(box.value).toBe(""));
    expect(document.body.innerHTML).not.toContain("KEY-MATERIAL");
  });
});
