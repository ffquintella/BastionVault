/**
 * T145 — the Rustion lifecycle chip renews and ends only its own
 * window's bastion session: every call carries the local session token
 * and nothing else, so the host (which refuses a window not holding the
 * token) is the one that picks the bastion, session and correlation ids.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const h = vi.hoisted(() => ({ mockInvoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => h.mockInvoke(...args),
}));

import { RustionSessionChip } from "../components/RustionSessionChip";

const TOKEN = "sess_0123456789abcdef0123456789abcdef";

const BUNDLE = {
  session_id: "rs_mine",
  bastion_id: "bastion_mine",
  bastion_name: "edge-1",
  correlation_id: "corr_mine",
  expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
  max_renewals: 3,
  protocol: "sftp",
};

beforeEach(() => {
  h.mockInvoke.mockReset();
  h.mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "session_rustion_info":
        return Promise.resolve(BUNDLE);
      case "session_rustion_renew":
        return Promise.resolve({
          sessionId: "rs_mine",
          expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
          renewalsUsed: 1,
          maxRenewals: 3,
          bastionId: "bastion_mine",
        });
      case "session_rustion_kill":
        return Promise.resolve({ sessionId: "rs_mine", terminatedAt: "now", bastionId: "bastion_mine" });
      default:
        return Promise.reject(new Error(`unexpected ${cmd}`));
    }
  });
});

const calls = () => h.mockInvoke.mock.calls.map(([cmd, args]) => ({ cmd, args }));

describe("RustionSessionChip", () => {
  it("reads, renews and ends the session by token only", async () => {
    render(<RustionSessionChip token={TOKEN} />);
    await screen.findByText("edge-1");

    fireEvent.click(screen.getByRole("button", { name: "Renew" }));
    await screen.findByText("renew 1/3");
    fireEvent.click(screen.getByRole("button", { name: "Terminate" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Terminate" })).toBeDisabled());

    expect(calls()).toEqual([
      { cmd: "session_rustion_info", args: { request: { token: TOKEN } } },
      { cmd: "session_rustion_renew", args: { request: { token: TOKEN, extendSecs: 1800 } } },
      { cmd: "session_rustion_kill", args: { request: { token: TOKEN } } },
    ]);
  });

  it("never reaches the raw-id commands", async () => {
    render(<RustionSessionChip token={TOKEN} />);
    await screen.findByText("edge-1");
    fireEvent.click(screen.getByRole("button", { name: "Renew" }));
    fireEvent.click(screen.getByRole("button", { name: "Terminate" }));
    await waitFor(() => expect(calls().some((c) => c.cmd === "session_rustion_kill")).toBe(true));
    expect(calls().map((c) => c.cmd)).not.toContain("rustion_session_renew");
    expect(calls().map((c) => c.cmd)).not.toContain("rustion_session_kill");
  });

  it("renders nothing for a direct session", async () => {
    h.mockInvoke.mockImplementation(() => Promise.resolve(null));
    const { container } = render(<RustionSessionChip token={TOKEN} />);
    await waitFor(() => expect(h.mockInvoke).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
