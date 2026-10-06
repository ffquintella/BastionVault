// T35 Phase 4 — the RDP clipboard / file-copy ceilings on the Rustion
// policy tier editor.
//
// Pins two behaviours the server's write semantics depend on:
//
//   - the editor loads a tier's stored clipboard knobs and sends them back
//     on Save, so changing the transport here never erases a clipboard pin;
//   - "Clear fields" followed by Save sends an explicit empty string — a
//     deliberate clear — rather than leaving the key out, which the server
//     reads as "unchanged".

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { RustionPolicyTierEditor } from "../components/RustionPolicyTierEditor";
import { CLIPBOARD_CEILING_OPTIONS } from "../lib/rustion";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function storedTier(over: Record<string, unknown> = {}) {
  return {
    name: "server",
    priority: 0,
    transport: "rustion-preferred",
    bastions: [],
    bastionGroup: "",
    recording: "always",
    clipboard: "off",
    clipboardFiles: "",
    lock: true,
    updatedAt: "2026-10-06T00:00:00Z",
    ...over,
  };
}

function writes(command: string) {
  return mockInvoke.mock.calls.filter(([cmd]) => cmd === command);
}

describe("RustionPolicyTierEditor clipboard ceilings", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("offers exactly the server's vocabulary plus unset", () => {
    expect(CLIPBOARD_CEILING_OPTIONS.map((o) => o.value)).toEqual([
      "",
      "off",
      "host-to-session",
      "session-to-host",
      "bidirectional",
    ]);
  });

  it("round-trips the stored knobs so a transport edit keeps the pin", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "rustion_policy_type_read") return Promise.resolve(storedTier());
      return Promise.resolve(undefined);
    });
    render(
      <ToastProvider>
        <RustionPolicyTierEditor tier="type" id="server" />
      </ToastProvider>,
    );

    const clipboard = (await screen.findByLabelText("RDP clipboard")) as HTMLSelectElement;
    await waitFor(() => expect(clipboard.value).toBe("off"));
    const files = screen.getByLabelText("RDP file copy") as HTMLSelectElement;
    expect(files.value).toBe("");

    await userEvent.selectOptions(screen.getByLabelText("Transport"), "rustion-required");
    await userEvent.selectOptions(files, "session-to-host");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(writes("rustion_policy_type_write")).toHaveLength(1));
    const [, args] = writes("rustion_policy_type_write")[0];
    expect(args).toMatchObject({
      typeName: "server",
      input: {
        transport: "rustion-required",
        clipboard: "off",
        clipboardFiles: "session-to-host",
        lock: true,
      },
    });
  });

  it("sends an explicit empty string when the fields are cleared", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "rustion_policy_asset_group_read")
        return Promise.resolve(storedTier({ clipboardFiles: "off" }));
      return Promise.resolve(undefined);
    });
    render(
      <ToastProvider>
        <RustionPolicyTierEditor tier="asset-group" id="pci" />
      </ToastProvider>,
    );

    const clipboard = (await screen.findByLabelText("RDP clipboard")) as HTMLSelectElement;
    await waitFor(() => expect(clipboard.value).toBe("off"));
    await userEvent.click(screen.getByRole("button", { name: "Clear fields" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(writes("rustion_policy_asset_group_write")).toHaveLength(1));
    const [, args] = writes("rustion_policy_asset_group_write")[0];
    expect(args.input.clipboard).toBe("");
    expect(args.input.clipboardFiles).toBe("");
    expect("clipboard" in args.input).toBe(true);
  });
});
