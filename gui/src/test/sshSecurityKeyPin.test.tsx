/**
 * The SSH security-key enrolment must be able to collect a PIN.
 *
 * The Rust side blocks the CTAP2 ceremony on `fido2-pin-request` and waits up
 * to two minutes for `fido2_submit_pin`. A card with no listener for that
 * event looks like it hangs on "Your key is asking for its PIN…" and then
 * fails with a timeout, which is what shipped before
 * `features/connect-mfa-and-fido2-ssh.md`'s enrolment card grew this modal.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { SshSecurityKeyCard } from "../components/SshSecurityKeyCard";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

/** Captured `listen` handlers, keyed by event name, so a test can drive the
 *  ceremony's progress exactly as the Rust side would. */
const handlers = new Map<string, (e: { payload: string }) => void>();
vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: string }) => void) => {
    handlers.set(event, handler);
    return Promise.resolve(() => handlers.delete(event));
  },
  emit: () => Promise.resolve(),
}));

const NOT_ENROLLED = {
  mount: "userpass/",
  name: "alice",
  enrolled: false,
  algorithm: "",
  public_key: "",
  credential_id: "",
  application: "",
  comment: "",
  updated_at: "",
};

function renderCard() {
  return render(
    <ToastProvider>
      <SshSecurityKeyCard />
    </ToastProvider>,
  );
}

describe("SSH security key — PIN collection", () => {
  beforeEach(() => {
    handlers.clear();
    mockInvoke.mockReset();
  });

  it("prompts for the PIN and relays it to the ceremony", async () => {
    // The enrolment never resolves on its own here: the real one is blocked
    // inside the authenticator until the PIN arrives.
    let finishEnrol: (v: unknown) => void = () => {};
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "ssh_security_key_self_read") return Promise.resolve(NOT_ENROLLED);
      if (cmd === "ssh_security_key_enroll")
        return new Promise((resolve) => { finishEnrol = resolve; });
      if (cmd === "fido2_submit_pin") return Promise.resolve();
      return Promise.resolve();
    });

    renderCard();
    const button = await screen.findByRole("button", { name: /enrol ssh security key/i });
    await userEvent.click(button);

    // Rust asks for the PIN.
    handlers.get("fido2-status")?.({ payload: "pin-required" });
    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });

    const input = await screen.findByPlaceholderText("Enter PIN");
    await userEvent.type(input, "123456");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("fido2_submit_pin", { pin: "123456" }),
    );

    finishEnrol({ ...NOT_ENROLLED, enrolled: true, algorithm: "sk-ssh-ed25519@openssh.com",
      public_key: "sk-ssh-ed25519@openssh.com AAAA test", application: "ssh:" });
    await waitFor(() =>
      expect(screen.getByText(/sk-ssh-ed25519@openssh.com AAAA test/)).toBeTruthy(),
    );
  });

  it("reports the remaining attempts on a wrong PIN", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "ssh_security_key_self_read") return Promise.resolve(NOT_ENROLLED);
      if (cmd === "ssh_security_key_enroll") return new Promise(() => {});
      return Promise.resolve();
    });

    renderCard();
    await userEvent.click(
      await screen.findByRole("button", { name: /enrol ssh security key/i }),
    );

    handlers.get("fido2-pin-request")?.({ payload: "invalid-pin:2" });
    expect(await screen.findByText(/2 attempts remaining/i)).toBeTruthy();
  });

  it("aborts the ceremony when the operator cancels, rather than letting it time out", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "ssh_security_key_self_read") return Promise.resolve(NOT_ENROLLED);
      if (cmd === "ssh_security_key_enroll") return new Promise(() => {});
      return Promise.resolve();
    });

    renderCard();
    await userEvent.click(
      await screen.findByRole("button", { name: /enrol ssh security key/i }),
    );

    handlers.get("fido2-pin-request")?.({ payload: "pin-required" });
    await screen.findByPlaceholderText("Enter PIN");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    // An empty PIN is the abort signal: it drops the CTAP sender in Rust.
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("fido2_submit_pin", { pin: "" }),
    );
  });

  it("names the blocked states instead of stalling on 'Working…'", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "ssh_security_key_self_read") return Promise.resolve(NOT_ENROLLED);
      if (cmd === "ssh_security_key_enroll") return new Promise(() => {});
      return Promise.resolve();
    });

    renderCard();
    await userEvent.click(
      await screen.findByRole("button", { name: /enrol ssh security key/i }),
    );

    handlers.get("fido2-status")?.({ payload: "pin-blocked" });
    // Both the button label and the line under it mirror the status.
    expect((await screen.findAllByText(/key locked/i)).length).toBeGreaterThan(0);
  });
});
