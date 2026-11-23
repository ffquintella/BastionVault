import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
const mockOpen = vi.fn();
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: (...args: unknown[]) => mockOpen(...args),
}));

import { SsoTestModal } from "./SsoTestModal";

const GOOD = {
  ok: true,
  steps: [
    { name: "Browser sign-in and redirect back", status: "ok", detail: "redirected" },
    { name: "Vault policies granted", status: "ok", detail: "default, readonly" },
    { name: "Test token revoked", status: "ok", detail: "revoked" },
  ],
  display_name: "alice",
  role: "staff",
  subject: "sub-1",
  groups: ["admins"],
  policies: ["default", "readonly"],
  ttl_secs: 3600,
  metadata: { email: "alice@example.com", groups: '["admins"]' },
  token_revoked: true,
};

function setup() {
  return render(<SsoTestModal mount="okta" displayName="Acme SSO" onClose={() => undefined} />);
}

describe("SsoTestModal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockOpen.mockReset();
  });

  it("opens the IdP URL, then shows the received fields and a passing verdict", async () => {
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "oidc_login_start") return { sessionId: "s1", authUrl: "https://idp/auth" };
      if (cmd === "oidc_test_complete") return GOOD;
      throw new Error(`unexpected ${cmd}`);
    });
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Start test" }));

    await screen.findByText(/would work/i);
    expect(mockOpen).toHaveBeenCalledWith("https://idp/auth");
    expect(mockInvoke).toHaveBeenCalledWith("oidc_login_start", { mount: "okta" });
    // Fields from the provider.
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("sub-1")).toBeInTheDocument();
    // Shown in the step list and in the received-fields table.
    expect(screen.getAllByText("default, readonly")).toHaveLength(2);
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();
    // Discovery step is prepended once the flow got past start.
    expect(screen.getByText("Discovery and authorization URL")).toBeInTheDocument();
    // The test never uses the real login-complete command.
    expect(mockInvoke.mock.calls.map((c) => c[0])).not.toContain("oidc_login_complete");
  });

  it("reports a failed vault step as a failing verdict without received fields", async () => {
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "oidc_login_start") return { sessionId: "s1", authUrl: "https://idp/auth" };
      return {
        ...GOOD,
        ok: false,
        steps: [
          { name: "Browser sign-in and redirect back", status: "ok", detail: "redirected" },
          {
            name: "Token exchange, ID-token and role checks",
            status: "fail",
            detail: "oidc: bound_claim `hd` did not match allowed values",
          },
        ],
        display_name: "",
        policies: [],
      };
    });
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Start test" }));

    await screen.findByText(/would not work/i);
    expect(screen.getByText(/bound_claim `hd` did not match/)).toBeInTheDocument();
    expect(screen.queryByText("Received from the provider")).not.toBeInTheDocument();
  });

  it("shows a start failure as the discovery step and releases the session", async () => {
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "oidc_login_start") throw "oidc: auth/okta/auth_url: certificate verify failed";
      throw new Error(`unexpected ${cmd}`);
    });
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Start test" }));

    await screen.findByText(/would not work/i);
    expect(screen.getByText("Discovery and authorization URL")).toBeInTheDocument();
    expect(screen.getByText(/certificate verify failed/)).toBeInTheDocument();
    expect(mockOpen).not.toHaveBeenCalled();
  });

  it("shows the vault's TLS error text verbatim, legacy TLS client included (T551)", async () => {
    const message =
      "oidc: discovery: Request failed: legacy TLS 1.2 (CBC) client: server sent fatal alert handshake_failure (40)";
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "oidc_login_start") throw message;
      throw new Error(`unexpected ${cmd}`);
    });
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Start test" }));

    await screen.findByText(/would not work/i);
    expect(screen.getByText(message)).toBeInTheDocument();
  });

  it("cancels the pending session when the browser cannot be opened", async () => {
    mockOpen.mockRejectedValue(new Error("no browser"));
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "oidc_login_start") return { sessionId: "s9", authUrl: "https://idp/auth" };
      return undefined;
    });
    setup();
    await userEvent.click(screen.getByRole("button", { name: "Start test" }));

    await screen.findByText("Opening the browser");
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith("oidc_login_cancel", { sessionId: "s9" }));
  });
});
