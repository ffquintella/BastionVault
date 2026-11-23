/**
 * The SSO provider editor's legacy TLS 1.2 CBC toggle (T551): loads the
 * stored value, and always sends it — `false` included — so switching it
 * off really clears it.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

import { SsoProviderModal } from "./SettingsPage";
import type { SsoAdminInput, SsoAdminProviderOidc } from "../lib/api";

function provider(legacy: boolean, available: boolean | null = true): SsoAdminProviderOidc {
  return {
    kind: "oidc",
    mount: "fgv",
    display_name: "Corporate SSO",
    default_role: "user",
    config: {
      kind: "oidc",
      discovery_url: "https://idp.example/sso/oauth/abc",
      client_id: "cid",
      client_secret_set: true,
      scopes: ["openid", "profile"],
      allowed_redirect_uris: [],
      discovery_ca_pem: "",
      discovery_legacy_tls: legacy,
      legacy_tls_available: available,
    },
    role: {
      kind: "oidc",
      name: "user",
      user_claim: "preferred_username",
      groups_claim: "",
      bound_audiences: [],
      bound_claims_json: "",
      policies: ["default"],
      token_ttl_secs: 3600,
    },
  };
}

function lastSaved(onSave: ReturnType<typeof vi.fn>): SsoAdminInput {
  expect(onSave).toHaveBeenCalled();
  return onSave.mock.calls[onSave.mock.calls.length - 1][0] as SsoAdminInput;
}

function legacyFlag(input: SsoAdminInput): unknown {
  return input.kind === "oidc" ? input.config.discovery_legacy_tls : undefined;
}

describe("SsoProviderModal legacy TLS toggle", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(null);
  });

  it("is off by default on a new provider and sends an explicit false", async () => {
    const onSave = vi.fn();
    render(<SsoProviderModal provider={null} onSave={onSave} onClose={() => undefined} />);
    const toggle = screen.getByRole("switch", { name: /legacy TLS 1\.2 \(CBC\)/i });
    expect(toggle).not.toBeChecked();
    expect(screen.getByText(/weaker than the GCM \/ ChaCha20 suites/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Create Provider" }));
    await waitFor(() => expect(legacyFlag(lastSaved(onSave))).toBe(false));
  });

  it("can be turned on and is sent as true", async () => {
    const onSave = vi.fn();
    render(<SsoProviderModal provider={provider(false)} onSave={onSave} onClose={() => undefined} />);
    await userEvent.click(screen.getByRole("switch"));
    await userEvent.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(legacyFlag(lastSaved(onSave))).toBe(true));
  });

  it("shows the persisted value and turning it off sends false, not nothing", async () => {
    const onSave = vi.fn();
    render(<SsoProviderModal provider={provider(true)} onSave={onSave} onClose={() => undefined} />);
    const toggle = screen.getByRole("switch");
    expect(toggle).toBeChecked();
    await userEvent.click(toggle);
    expect(toggle).not.toBeChecked();
    await userEvent.click(screen.getByRole("button", { name: "Save Changes" }));
    await waitFor(() => {
      const input = lastSaved(onSave);
      expect(input.kind).toBe("oidc");
      if (input.kind === "oidc") {
        expect(Object.prototype.hasOwnProperty.call(input.config, "discovery_legacy_tls")).toBe(true);
        expect(input.config.discovery_legacy_tls).toBe(false);
      }
    });
  });

  it("shows the compiled-out state from the vault's read and from a refused save", () => {
    const { unmount } = render(
      <SsoProviderModal provider={provider(false, false)} onSave={vi.fn()} onClose={() => undefined} />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/built without the legacy TLS client/i);
    expect(screen.getByRole("switch")).toBeDisabled();
    unmount();

    render(
      <SsoProviderModal
        provider={provider(true, null)}
        onSave={vi.fn()}
        onClose={() => undefined}
        saveError="oidc: `oidc_discovery_legacy_tls` is true, but this vault was built without the legacy TLS 1.2 CBC client"
      />,
    );
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("switch")).toBeEnabled();
  });
});
