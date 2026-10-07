/**
 * The Resources page with a credential-provider profile (features/self-accounts.md
 * §6, T103 Phase 4): the card quick-Connect runs candidates → picker → MFA →
 * open, and the profile editor offers only the approved providers that serve
 * the profile's protocol, hides the username, and asks for `require_mfa`.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({
  open: () => Promise.resolve(),
}));

const RESOURCE = "dc01";

const PROVIDER_PROFILE = {
  id: "p_sa",
  name: "Self-account",
  protocol: "rdp",
  is_default: true,
  require_mfa: true,
  credential_source: { kind: "provider", provider: "self-accounts" },
};

const SECRET_PROFILE = {
  id: "p_secret",
  name: "Shared",
  protocol: "rdp",
  username: "Administrator",
  credential_source: { kind: "secret", secret_id: "admin" },
};

const PROVIDERS = [
  { name: "self-accounts", display_name: "Self-account", protocols: ["ssh", "rdp", "web"], secret_kinds: ["password", "ssh-key"] },
  { name: "web-only", display_name: "Web vault", protocols: ["web"], secret_kinds: ["password"] },
];

function mockVault(profiles: unknown[]) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "resource_types_read":
        return Promise.resolve(null);
      case "list_asset_groups":
      case "asset_groups_for_resource":
        return Promise.resolve({ groups: [] });
      case "search_resources":
        return Promise.resolve({
          items: [
            {
              name: RESOURCE,
              type: "server",
              hostname: "dc01.corp.example.com",
              connect_profiles: profiles.map((p) => ({
                protocol: (p as { protocol: string }).protocol,
                credential_source: { kind: (p as { credential_source: { kind: string } }).credential_source.kind },
              })),
            },
          ],
          total: 1,
          has_more: false,
        });
      case "read_resource":
        return Promise.resolve({
          name: RESOURCE,
          type: "server",
          os_type: "windows",
          hostname: "dc01.corp.example.com",
          connection_profiles: profiles,
        });
      case "capabilities_self":
        return Promise.resolve({ paths: { [`resources/secrets/${RESOURCE}/`]: ["read"] } });
      case "connect_credential_providers":
        return Promise.resolve(PROVIDERS);
      case "connect_provider_candidates":
        return Promise.resolve({
          provider: "self-accounts",
          display_name: "Self-account",
          protocol: "rdp",
          resource_type: "server",
          os_type: "windows",
          target: { kind: "host", host: "dc01.corp.example.com", port: 3389 },
          candidates: [
            { id: "sa_1", label: "Domain admin", username: "felipe.adm", domain: "CORP", secret_kind: "password",
              has_totp: false, last_used_at: null },
            { id: "sa_2", label: "Helpdesk", username: "felipe.hd", domain: "CORP", secret_kind: "password",
              has_totp: false, last_used_at: null },
          ],
          hidden: 0,
        });
      case "connect_mfa_begin":
        return Promise.resolve({ required: false, methods: [] });
      case "session_open_rdp":
        return Promise.resolve({ token: "t" });
      case "list_resource_secrets":
        return Promise.resolve({ keys: ["admin"] });
      case "resource_login_class":
        return Promise.resolve({ login_class: "shared-credential", login_class_source: "default", login_class_chain: [] });
      default:
        return Promise.reject(new Error(`unmocked: ${cmd}`));
    }
  });
}

async function renderResources() {
  const { ResourcesPage } = await import("../routes/ResourcesPage");
  render(
    <MemoryRouter>
      <ToastProvider>
        <ResourcesPage />
      </ToastProvider>
    </MemoryRouter>,
  );
  await screen.findByText(RESOURCE);
}

const commands = () => mockInvoke.mock.calls.map((c) => c[0] as string);

describe("Resources: a credential-provider profile", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useAuthStore.setState({ token: "t", isAuthenticated: true, policies: ["admin"], entityId: "entity-1" });
  });

  it("quick-Connect asks for the account before MFA and opens with it", async () => {
    mockVault([PROVIDER_PROFILE]);
    await renderResources();
    await userEvent.click(screen.getAllByTitle("Connect")[0]);

    const dialog = (await screen.findByText("Choose an account")).closest("div.rounded-xl") as HTMLElement;
    expect(within(dialog).getByTestId("provider-picker-target")).toHaveTextContent("dc01.corp.example.com:3389");
    expect(commands()).not.toContain("connect_mfa_begin");

    const options = within(dialog).getAllByRole("option");
    await userEvent.click(within(options[1]).getByText("Helpdesk"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Connect" }));

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("session_open_rdp", {
        request: expect.objectContaining({ resource_name: RESOURCE, profile_id: "p_sa", provider_account_id: "sa_2" }),
      }),
    );
    const order = commands().filter((c) =>
      ["connect_provider_candidates", "connect_mfa_begin", "session_open_rdp"].includes(c),
    );
    expect(order).toEqual(["connect_provider_candidates", "connect_mfa_begin", "session_open_rdp"]);
  });

  it("the editor offers only approved providers for the protocol and hides the username", async () => {
    // Two profiles and no default: the quick-Connect hands off to the
    // Connection tab, where the editor lives.
    mockVault([{ ...SECRET_PROFILE }, { ...PROVIDER_PROFILE, is_default: false }]);
    await renderResources();
    await userEvent.click(screen.getAllByTitle("Connect")[0]);
    await screen.findByText("Connection profiles");

    await userEvent.click(screen.getByRole("button", { name: "+ Add profile" }));
    const source = (await screen.findByLabelText("Credential source")) as HTMLSelectElement;
    await waitFor(() =>
      expect(within(source).getByRole("option", { name: "Self-account (pick at connect)" })).toBeInTheDocument(),
    );
    // A provider that does not serve RDP is not offered.
    expect(within(source).queryByRole("option", { name: /Web vault/ })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();

    await userEvent.selectOptions(source, "provider:self-accounts");
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
    // Without `require_mfa` the editor says the provider will refuse.
    expect(screen.getByRole("note")).toHaveTextContent(/Require MFA re-validation/);
    await userEvent.click(screen.getByRole("checkbox", { name: /Require MFA re-validation/ }));
    expect(screen.queryByText(/normally releases an account only/)).not.toBeInTheDocument();
  });

  it("keeps a profile with an unknown credential source through a save, and says so", async () => {
    // Written by a newer client: a known protocol, a source this build does
    // not know. Hidden here, never lost (spec §10, T102 rule).
    const future = {
      id: "p_future",
      name: "Vault bridge",
      protocol: "rdp",
      credential_source: { kind: "password-manager", vault: "corp" },
      later_field: [1, 2],
    };
    mockVault([{ ...SECRET_PROFILE }, { ...PROVIDER_PROFILE, is_default: false }, future]);
    const inner = mockInvoke.getMockImplementation()!;
    mockInvoke.mockImplementation((cmd: string, args: unknown) =>
      cmd === "write_resource" ? Promise.resolve(null) : inner(cmd, args),
    );
    await renderResources();
    await userEvent.click(screen.getAllByTitle("Connect")[0]);
    await screen.findByText("Connection profiles");

    expect(screen.getByText("1 profile uses an unsupported protocol or credential source.")).toBeInTheDocument();
    expect(screen.queryByText("Vault bridge")).not.toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Set default" })[0]);
    await waitFor(() => expect(commands()).toContain("write_resource"));
    const call = mockInvoke.mock.calls.find((c) => c[0] === "write_resource")!;
    const written = JSON.stringify(call[1]);
    expect(written).toContain(JSON.stringify(future));
  });
});
