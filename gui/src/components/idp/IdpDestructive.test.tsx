/**
 * Destructive Identity Provider actions (T52 Phase 7) need a confirmation that
 * names the object and the consequence before any request is sent; the
 * permanent ones (identity removal, environment retirement) also need the
 * name typed.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../ui/Toast";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { IdpIdentitiesTab } from "./IdpIdentitiesTab";
import { IdpEnvironmentsCard } from "./IdpEnvironmentsCard";
import { KeyRingCard } from "./KeyRingCard";
import type { IdpDirectory } from "./directory";

function directory(state: "active" | "disabled"): IdpDirectory {
  return {
    identities: [{ entity_id: "e-1", info: { login: "alice", uid: 80017, primary_gid: 80017, state } }],
    environments: [{ name: "prod", info: { namespace: "", state: "active", roles: ["sysadmin"] } }],
    activeEnvironments: ["prod"],
    reload: vi.fn().mockResolvedValue(undefined),
  };
}

function wrap(ui: React.ReactNode) {
  return render(<ToastProvider>{ui}</ToastProvider>);
}

const sent = (cmd: string) => mockInvoke.mock.calls.filter((c) => c[0] === cmd);

beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "idp_read_settings") return Promise.resolve({ data: { uid_min: 80000, uid_max: 999999, gid_min: 80000, gid_max: 999999, uid_used: 1, uid_retired: 0, gid_used: 1, gid_retired: 0 }, warnings: [] });
    if (cmd === "idp_set_identity_state")
      return Promise.resolve({ data: { login: "alice", state: "removed", revoked_certificates: 2, deny_feed_version: 9 }, warnings: [] });
    if (cmd === "idp_read_keys") return Promise.resolve({ data: { keys: [] }, warnings: [] });
    if (cmd === "idp_rotate_keys") return Promise.resolve({ data: { keys: [] }, warnings: [] });
    if (cmd === "idp_delete") return Promise.resolve({ data: {}, warnings: [] });
    return Promise.reject(new Error(`unexpected ${cmd}`));
  });
});

describe("identity lifecycle confirmations", () => {
  it("disable names the identity and what it revokes before sending", async () => {
    const user = userEvent.setup();
    wrap(<IdpIdentitiesTab directory={directory("active")} />);
    await user.click(await screen.findByRole("button", { name: "Disable" }));

    expect(screen.getByText(/Disable alice \(uid 80017\)\?/)).toBeInTheDocument();
    expect(screen.getByText(/marked revoked and listed in the KRL and the deny feed/)).toBeInTheDocument();
    expect(sent("idp_set_identity_state")).toHaveLength(0);

    const disableButtons = screen.getAllByRole("button", { name: "Disable" });
    await user.click(disableButtons[disableButtons.length - 1]);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("idp_set_identity_state", { entityId: "e-1", target: "disabled", reason: null }),
    );
  });

  it("removal is permanent and needs the login typed", async () => {
    const user = userEvent.setup();
    const dir = directory("disabled");
    wrap(<IdpIdentitiesTab directory={dir} />);
    await user.click(await screen.findByRole("button", { name: "Remove" }));

    expect(screen.getByText(/Removal is permanent\. uid 80017 and its primary gid are retired/)).toBeInTheDocument();
    expect(screen.getByText(/none is ever reused, and the identity can never be reinstated/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: /remove permanently/i });
    expect(confirm).toBeDisabled();

    await user.type(screen.getByLabelText(/Type "alice" to confirm/), "alic");
    expect(confirm).toBeDisabled();
    await user.click(confirm);
    expect(sent("idp_set_identity_state")).toHaveLength(0);

    await user.type(screen.getByLabelText(/Type "alice" to confirm/), "e");
    await user.type(screen.getByLabelText(/Reason/), "left the company");
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("idp_set_identity_state", { entityId: "e-1", target: "removed", reason: "left the company" }),
    );
    await waitFor(() => expect(dir.reload).toHaveBeenCalled());
  });

  it("cancel sends nothing", async () => {
    const user = userEvent.setup();
    wrap(<IdpIdentitiesTab directory={directory("disabled")} />);
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(sent("idp_set_identity_state")).toHaveLength(0);
  });
});

describe("environment retirement", () => {
  it("names the permanence and needs the environment typed", async () => {
    const user = userEvent.setup();
    wrap(<IdpEnvironmentsCard directory={directory("active")} />);
    await user.click(screen.getByRole("button", { name: "Retire" }));
    expect(screen.getByText(/the name is never reused/)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: /retire permanently/i });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByPlaceholderText("prod"), "prod");
    await user.click(confirm);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("idp_delete", { kind: "environment", name: "prod" }));
  });
});

describe("key rotation", () => {
  it("states the consequence and rotates only on confirm", async () => {
    const user = userEvent.setup();
    wrap(<KeyRingCard ring="oidc" />);
    await user.click(await screen.findByRole("button", { name: /rotate key/i }));
    expect(screen.getByText(/stays in the JWKS for 24h/)).toBeInTheDocument();
    expect(sent("idp_rotate_keys")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: /^rotate$/i }));
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("idp_rotate_keys", { ring: "oidc", overlap: "24h" }));
  });
});
