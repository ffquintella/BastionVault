// The Connection tab's "Bastion routing" panel must agree with the route
// Connect actually takes. With no pinned bastions and no group the
// dispatcher falls back to the whole registry as a random pool, so it can
// always name a candidate — even for a `direct` resource, where Connect
// dials the target from this machine. The panel used to show that pool
// ("Will try: …") next to a "direct" transport chip.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { RustionDispatcherPreview } from "../components/RustionDispatcherPreview";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const POOL_PREVIEW = {
  mode: "random-pool",
  groupName: "",
  sourceTier: "default",
  candidates: [{ id: "rt_1", name: "bastion-a", status: "up" }],
  dropped: [],
};

function effective(transport: string, bastions: string[]) {
  return {
    transport,
    transportSource: "default",
    bastions,
    bastionGroup: "",
    bastionsSource: "default",
    recording: "off",
    recordingSource: "default",
    lockedBy: [],
    lockViolation: null,
    clipboard: "",
    clipboardSource: "",
    clipboardFiles: "",
    clipboardFilesSource: "",
    clipboardLockedBy: [],
    clipboardLockConflict: null,
  };
}

function mockPolicy(policy: ReturnType<typeof effective> | Error) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "rustion_policy_effective":
        return policy instanceof Error ? Promise.reject(policy) : Promise.resolve(policy);
      case "rustion_dispatcher_preview":
        return Promise.resolve(POOL_PREVIEW);
      default:
        return Promise.reject(new Error(`unexpected command ${cmd}`));
    }
  });
}

function renderPreview() {
  return render(
    <RustionDispatcherPreview resourceId="host1" resourceType="server" assetGroupIds={[]} />,
  );
}

async function settled() {
  await waitFor(() => {
    const cmds = mockInvoke.mock.calls.map((c) => c[0]);
    expect(cmds).toContain("rustion_policy_effective");
    expect(cmds).toContain("rustion_dispatcher_preview");
  });
}

describe("RustionDispatcherPreview", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("hides the random pool when the effective transport is direct", async () => {
    mockPolicy(effective("direct", []));
    renderPreview();
    await settled();
    expect(screen.queryByText("Bastion routing")).toBeNull();
    expect(screen.queryByText("bastion-a")).toBeNull();
  });

  it("hides it for rustion-preferred with no bastion, which Connect dials direct", async () => {
    mockPolicy(effective("rustion-preferred", []));
    renderPreview();
    await settled();
    expect(screen.queryByText("Bastion routing")).toBeNull();
  });

  it("hides it when the policy cannot be resolved", async () => {
    mockPolicy(new Error("boom"));
    renderPreview();
    await settled();
    expect(screen.queryByText("Bastion routing")).toBeNull();
  });

  it("shows the candidates when the transport is rustion-required", async () => {
    mockPolicy(effective("rustion-required", []));
    renderPreview();
    expect(await screen.findByText("Bastion routing")).toBeTruthy();
    expect(screen.getByText("bastion-a")).toBeTruthy();
  });
});
