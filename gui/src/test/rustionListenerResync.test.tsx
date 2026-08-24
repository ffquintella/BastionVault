// Regression test for the listener Re-sync affordance in
// RustionBastionsTab.
//
// Background: listener discovery (`GET /v1/listeners` on the bastion)
// fires exactly once, best-effort, at enrolment. The SSH host-key /
// RDP TLS pins it captures are what the dialler pins against. Until
// this button existed, a bastion enrolled before it advertised pins
// (pre-listener-schema-v2 Rustion) — or one whose host key rotated —
// stayed on empty pins forever: the row showed amber "SSH unpinned" /
// "RDP unpinned" and Connect hopped unpinned, with no operator
// affordance in the GUI or the CLI to re-read them.
//
// Pins: the amber badges render off the stored record, clicking
// Re-sync invokes `rustion_target_refresh_listeners` for that target,
// and the row re-reads and flips to the green pinned badges.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { RustionBastionsTab } from "../components/RustionBastionsTab";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const SSH_PIN = "SHA256:Y2eA5ErhvCj2E7FhyyNTBgF1Mv66jehyet6dJh9nRTo";
const RDP_PIN = "sha256:b1fc6e636f11008e4b0f21835d8b85b5eb98d79fba4a4053e010077b9f090f49";

/** Minimal target record — only the fields the row renders. */
function target(pins: { ssh: string; rdp: string }) {
  return {
    id: "rt_test",
    name: "bastion-dev",
    endpoint: "bastion.example.com:9443",
    description: "",
    enabled: true,
    tags: [],
    fingerprint: "",
    kem_public_key: "",
    public_key_ed25519: "",
    public_key_mldsa65: "",
    default_recording_dir: "",
    tls_pinned_cert_pem: "",
    tls_pinned: false,
    created_at: "2026-07-10T13:44:05Z",
    updated_at: "2026-07-10T13:44:05Z",
    // Discovery ran at enrolment — which is exactly why an empty pin
    // here must not be read as "this bastion cannot be pinned".
    listeners_synced_at: "2026-07-10T13:44:05Z",
    ssh_host_key_fingerprint: pins.ssh,
    rdp_tls_pin_sha256: pins.rdp,
    ssh_listener_host: "",
    ssh_listener_port: 2222,
    rdp_listener_host: "",
    rdp_listener_port: 3389,
  };
}

describe("RustionBastionsTab — listener Re-sync", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("re-reads the bastion's pins and flips the unpinned badges", async () => {
    const user = userEvent.setup();
    // First list call returns the stale (empty-pin) record; after the
    // refresh command fires, the reload sees the discovered pins.
    let refreshed = false;
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "rustion_target_list":
          return Promise.resolve([
            refreshed
              ? target({ ssh: SSH_PIN, rdp: RDP_PIN })
              : target({ ssh: "", rdp: "" }),
          ]);
        case "rustion_target_refresh_listeners":
          refreshed = true;
          return Promise.resolve(target({ ssh: SSH_PIN, rdp: RDP_PIN }));
        case "rustion_target_health_all":
          return Promise.resolve([]);
        case "rustion_deployment_id_read":
          return Promise.resolve("");
        default:
          return Promise.resolve(null);
      }
    });

    render(
      <ToastProvider>
        <RustionBastionsTab />
      </ToastProvider>,
    );

    expect(await screen.findByText("SSH unpinned")).toBeInTheDocument();
    expect(screen.getByText("RDP unpinned")).toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: "Re-sync" }));

    await waitFor(() => {
      expect(
        mockInvoke.mock.calls.some(
          ([c, a]) =>
            c === "rustion_target_refresh_listeners" &&
            (a as { id: string }).id === "rt_test",
        ),
      ).toBe(true);
    });

    expect(await screen.findByText("SSH host-key pinned")).toBeInTheDocument();
    expect(screen.getByText("RDP TLS pinned")).toBeInTheDocument();
    expect(screen.queryByText("SSH unpinned")).not.toBeInTheDocument();
  });
});
