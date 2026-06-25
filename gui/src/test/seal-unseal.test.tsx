import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Mock the Tauri invoke API at the module level (mirrors pages.test.tsx).
const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { UnsealModal } from "../components/UnsealModal";
import type { VaultStatus, UnsealOutcome, RemoteProfile } from "../lib/types";

const UNSEALED: VaultStatus = { initialized: true, sealed: false, has_vault: true };
const STILL_SEALED: VaultStatus = { initialized: true, sealed: true, has_vault: true };

function outcome(status: VaultStatus, nodes: UnsealOutcome["nodes"] = []): UnsealOutcome {
  return { status, nodes };
}

describe("UnsealModal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("embedded: submits with no key (uses the cached key) and reports unsealed", async () => {
    mockInvoke.mockResolvedValue(
      outcome(UNSEALED, [
        { address: "embedded", sealed: false, progress: null, threshold: null, error: null },
      ]),
    );
    const onUnsealed = vi.fn();
    render(
      <UnsealModal open onClose={() => {}} onUnsealed={onUnsealed} mode="Embedded" />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(onUnsealed).toHaveBeenCalledWith(UNSEALED));
    // Empty optional field => null key forwarded to the command.
    expect(mockInvoke).toHaveBeenCalledWith("unseal_vault", { unsealKeyHex: null });
  });

  it("remote: requires a key before invoking the command", async () => {
    const onUnsealed = vi.fn();
    render(
      <UnsealModal open onClose={() => {}} onUnsealed={onUnsealed} mode="Remote" />,
    );

    await userEvent.click(screen.getByRole("button", { name: "Unseal" }));

    expect(await screen.findByText(/unseal key is required/i)).toBeInTheDocument();
    expect(mockInvoke).not.toHaveBeenCalled();
    expect(onUnsealed).not.toHaveBeenCalled();
  });

  it("remote cluster: fans the share out, shows per-node progress while still sealed", async () => {
    mockInvoke.mockResolvedValue(
      outcome(STILL_SEALED, [
        { address: "https://n1:8200", sealed: true, progress: 1, threshold: 3, error: null },
        { address: "https://n2:8200", sealed: true, progress: 1, threshold: 3, error: null },
        { address: "https://n3:8200", sealed: null, progress: null, threshold: null, error: "sys/unseal failed: timeout" },
      ]),
    );
    const onUnsealed = vi.fn();
    render(
      <UnsealModal open onClose={() => {}} onUnsealed={onUnsealed} mode="Remote" />,
    );

    await userEvent.type(screen.getByLabelText(/unseal key/i), "deadbeef");
    await userEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("unseal_vault", { unsealKeyHex: "deadbeef" }),
    );
    expect(onUnsealed).toHaveBeenCalledWith(STILL_SEALED);
    expect(await screen.findByText(/still sealed/i)).toBeInTheDocument();
    // Per-node breakdown: 2 of 3 nodes reached, progress shown, one errored.
    expect(screen.getByText(/2\/3 reached/)).toBeInTheDocument();
    expect(screen.getByText("https://n1:8200")).toBeInTheDocument();
    expect(screen.getAllByText(/sealed \(1\/3\)/)).toHaveLength(2);
    expect(screen.getByText("error")).toBeInTheDocument();
  });

  it("explicit profile: unseals against the given profile (not the connected vault)", async () => {
    // The Connect screen passes a `profile` when the cluster connect
    // itself failed sealed — there is no live connection, so the modal
    // must target `remote_unseal_profile` with that profile + key
    // rather than the connected `unseal_vault` path.
    const profile: RemoteProfile = {
      name: "HML - Cluster",
      address: "esi.fgv.br",
      tls_skip_verify: false,
    };
    mockInvoke.mockResolvedValue(
      outcome(UNSEALED, [
        { address: "https://n1:5200", sealed: false, progress: null, threshold: null, error: null },
      ]),
    );
    const onUnsealed = vi.fn();
    render(
      <UnsealModal
        open
        onClose={() => {}}
        onUnsealed={onUnsealed}
        mode="Remote"
        profile={profile}
      />,
    );

    await userEvent.type(screen.getByLabelText(/unseal key/i), "deadbeef");
    await userEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("remote_unseal_profile", {
        profile,
        unsealKeyHex: "deadbeef",
      }),
    );
    expect(mockInvoke).not.toHaveBeenCalledWith("unseal_vault", expect.anything());
    expect(onUnsealed).toHaveBeenCalledWith(UNSEALED);
  });
});
