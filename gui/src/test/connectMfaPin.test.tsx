/**
 * The connect-time MFA prompt must be able to collect a security-key PIN.
 *
 * `connect_mfa_verify_fido2` runs the host's CTAP2 ceremony, which emits
 * `fido2-pin-request` and waits up to two minutes for `fido2_submit_pin`.
 * Before this, the prompt only mirrored `fido2-status`: it said "Your key is
 * asking for its PIN…" with no field to type it in and Cancel disabled, so a
 * PIN-protected key froze the Connect until the timeout.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConnectMfaPrompt, type PendingPrompt } from "../components/ConnectMfaPrompt";
import { fido2SubmitPin } from "../lib/api";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

const handlers = new Map<string, (e: { payload: string }) => void>();
vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: string }) => void) => {
    handlers.set(event, handler);
    return Promise.resolve(() => handlers.delete(event));
  },
  emit: () => Promise.resolve(),
}));

function pending(resolve: PendingPrompt["resolve"] = () => {}): PendingPrompt {
  return {
    resourceName: "evdc400",
    profileId: "p_1",
    profileName: "Default",
    challenge: { required: true, methods: ["fido2"], fido2: { challenge: "x" } },
    resolve,
  };
}

/** Start the key ceremony; it stays blocked until the test finishes it. */
async function startCeremony() {
  let finish: (v: unknown) => void = () => {};
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "connect_mfa_verify_fido2") return new Promise((r) => { finish = r; });
    return Promise.resolve();
  });
  const resolve = vi.fn();
  // The main window passes the relay; session windows do not.
  render(<ConnectMfaPrompt pending={pending(resolve)} submitPin={fido2SubmitPin} />);
  await userEvent.click(screen.getByRole("button", { name: "Verify and connect" }));
  await waitFor(() => expect(handlers.has("fido2-pin-request")).toBe(true));
  return { resolve, finish: (v: unknown) => finish(v) };
}

describe("Connect MFA — security-key PIN", () => {
  beforeEach(() => {
    handlers.clear();
    mockInvoke.mockReset();
  });

  it("asks for the PIN, relays it, and connects with the ticket", async () => {
    const { resolve, finish } = await startCeremony();

    handlers.get("fido2-status")?.({ payload: "pin-required" });
    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });

    const input = await screen.findByLabelText("Security key PIN");
    await userEvent.type(input, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Unlock key" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("fido2_submit_pin", { pin: "123456" }),
    );
    expect(screen.queryByLabelText("Security key PIN")).toBeNull();

    finish({ connect_ticket: "t1", expires_at: "", method: "fido2" });
    await waitFor(() => expect(resolve).toHaveBeenCalledWith({ connect_ticket: "t1" }));
  });

  it("reports the remaining attempts on a wrong PIN", async () => {
    await startCeremony();
    handlers.get("fido2-pin-request")?.({ payload: "invalid-pin:2" });
    expect(await screen.findByText(/2 attempts remaining/i)).toBeTruthy();
  });

  it("cancelling the PIN aborts the ceremony instead of waiting out the timeout", async () => {
    await startCeremony();
    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });
    await screen.findByLabelText("Security key PIN");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("fido2_submit_pin", { pin: "" }),
    );
  });

  it("says so when the relay is refused", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "connect_mfa_verify_fido2") return new Promise(() => {});
      if (cmd === "fido2_submit_pin") return Promise.reject(new Error("not allowed"));
      return Promise.resolve();
    });
    render(<ConnectMfaPrompt pending={pending()} submitPin={fido2SubmitPin} />);
    await userEvent.click(screen.getByRole("button", { name: "Verify and connect" }));
    await waitFor(() => expect(handlers.has("fido2-pin-request")).toBe(true));
    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });
    await userEvent.type(await screen.findByLabelText("Security key PIN"), "1");
    await userEvent.click(screen.getByRole("button", { name: "Unlock key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/main BastionVault window/);
  });

  it("in a session window (no relay) it says where to go and Cancel still works", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "connect_mfa_verify_fido2") return new Promise(() => {});
      return Promise.resolve();
    });
    const resolve = vi.fn();
    render(<ConnectMfaPrompt pending={pending(resolve)} />);
    await userEvent.click(screen.getByRole("button", { name: "Verify and connect" }));
    await waitFor(() => expect(handlers.has("fido2-pin-request")).toBe(true));
    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });

    expect(await screen.findByRole("alert")).toHaveTextContent(/main BastionVault window/);
    expect(screen.queryByLabelText("Security key PIN")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(resolve).toHaveBeenCalledWith(null);
    expect(mockInvoke).not.toHaveBeenCalledWith("fido2_submit_pin", expect.anything());
  });
});
