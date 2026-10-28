import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

const verifyTotp = vi.fn();
vi.mock("../lib/api", () => ({
  connectMfaVerifyTotp: (...args: unknown[]) => verifyTotp(...args),
  connectMfaVerifyFido2: vi.fn(),
}));

import { ConnectMfaPrompt } from "./ConnectMfaPrompt";

function renderPrompt() {
  return render(
    <ConnectMfaPrompt
      pending={{
        resourceName: "dc1",
        profileId: "p1",
        profileName: "Default",
        challenge: { required: true, methods: ["totp"] },
        resolve: vi.fn(),
      }}
    />,
  );
}

describe("ConnectMfaPrompt", () => {
  // Tauri rejects with a plain `{ message }` object, not an Error;
  // String() on it rendered "[object Object]" in place of the reason.
  it("shows the message of a non-Error command rejection", async () => {
    verifyTotp.mockRejectedValueOnce({ message: "invalid authenticator code" });
    renderPrompt();

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "039167" } });
    fireEvent.click(screen.getByRole("button", { name: /verify and connect/i }));

    await waitFor(() =>
      expect(screen.getByText("invalid authenticator code")).toBeTruthy(),
    );
    expect(screen.queryByText("[object Object]")).toBeNull();
  });
});
