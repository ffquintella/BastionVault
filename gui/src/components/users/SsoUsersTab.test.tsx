/**
 * SSO Users tab (T555): lists the `v2/sys/sso/users` directory and edits a
 * user's namespace access through the same ns-assignment key (`oidc/`,
 * `saml/`) the SSO login enforces.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../ui/Toast";
import { useAuthStore } from "../../stores/authStore";
import { useNamespaceStore } from "../../stores/namespaceStore";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("../Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

import { SsoUsersTab } from "./SsoUsersTab";
import { UsersPage } from "../../routes/UsersPage";

const FELIPE = {
  username: "felipe.quintella@fgv.br",
  mount: "oidc/",
  auth_method: "oidc",
  role: "default",
  subject: "sub-1",
  email: "felipe.quintella@fgv.br",
  email_source: "idp",
  first_login: "2026-11-24T10:00:00Z",
  last_login: "2026-11-24T12:00:00Z",
  login_count: 3,
};

function renderWithProviders(node: React.ReactNode) {
  useAuthStore.setState({ token: "root-token", isAuthenticated: true });
  useNamespaceStore.setState({ active: "" });
  render(
    <MemoryRouter>
      <ToastProvider>{node}</ToastProvider>
    </MemoryRouter>,
  );
}

function calls(cmd: string) {
  return mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("SsoUsersTab", () => {
  it("lists SSO users with the SSO badge, provider and email", async () => {
    mockInvoke.mockImplementation((cmd: string) =>
      Promise.resolve(cmd === "list_sso_users" ? [FELIPE] : null),
    );
    renderWithProviders(<SsoUsersTab availableNamespaces={[]} />);

    // Username and IdP e-mail are the same string here: both columns show it.
    expect(await screen.findAllByText("felipe.quintella@fgv.br")).toHaveLength(2);
    expect(screen.getByText("SSO")).toBeInTheDocument();
    expect(screen.getByText("OIDC · default")).toBeInTheDocument();
    expect(calls("list_sso_users")).toHaveLength(1);
  });

  it("saves namespace access under the SSO mount and leaves an unchanged email alone", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_sso_users":
          return Promise.resolve([FELIPE]);
        case "get_ns_assignment":
          return Promise.resolve({ namespaces: [] });
        default:
          return Promise.resolve(null);
      }
    });
    renderWithProviders(<SsoUsersTab availableNamespaces={["dti", "dti/esi"]} />);

    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    expect(calls("get_ns_assignment")[0][1]).toEqual({ mount: "oidc/", name: FELIPE.username });
    await userEvent.click(await screen.findByRole("button", { name: "dti" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(calls("set_ns_assignment")).toHaveLength(1));
    expect(calls("set_ns_assignment")[0][1]).toEqual({
      mount: "oidc/",
      name: FELIPE.username,
      namespaces: ["dti"],
    });
    expect(calls("update_sso_user")).toHaveLength(0);
    // No password control exists for an SSO user.
    expect(screen.queryByLabelText(/password/i)).toBeNull();
  });

  it("does not write namespace access it could not read", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_sso_users":
          return Promise.resolve([FELIPE]);
        case "get_ns_assignment":
          return Promise.reject(new Error("HTTP 403: permission denied"));
        default:
          return Promise.resolve(null);
      }
    });
    renderWithProviders(<SsoUsersTab availableNamespaces={["dti"]} />);

    await userEvent.click(await screen.findByRole("button", { name: "Edit" }));
    expect(await screen.findByText(/could not be read, so it is left unchanged/)).toBeInTheDocument();
    const emailInput = screen.getByPlaceholderText("e.g. user@example.com");
    await userEvent.clear(emailInput);
    await userEvent.type(emailInput, "felipe@corp.example");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(calls("update_sso_user")).toHaveLength(1));
    expect(calls("update_sso_user")[0][1]).toEqual({
      mount: "oidc/",
      username: FELIPE.username,
      email: "felipe@corp.example",
    });
    expect(calls("set_ns_assignment")).toHaveLength(0);
  });

  it("removes a record by mount and name", async () => {
    mockInvoke.mockImplementation((cmd: string) =>
      Promise.resolve(cmd === "list_sso_users" ? [FELIPE] : null),
    );
    renderWithProviders(<SsoUsersTab availableNamespaces={[]} />);

    await userEvent.click(await screen.findByRole("button", { name: "Remove" }));
    const confirm = screen.getAllByRole("button", { name: "Remove" });
    await userEvent.click(confirm[confirm.length - 1]);

    await waitFor(() => expect(calls("delete_sso_user")).toHaveLength(1));
    expect(calls("delete_sso_user")[0][1]).toEqual({ mount: "oidc/", username: FELIPE.username });
  });

  it("explains a server without the directory instead of failing", async () => {
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "list_sso_users"
        ? Promise.reject({ message: "HTTP 404: Logical backend path not supported." })
        : Promise.resolve(null),
    );
    renderWithProviders(<SsoUsersTab availableNamespaces={[]} />);
    expect(await screen.findByText(/no SSO user directory yet/)).toBeInTheDocument();
  });
});

describe("Users page tabs", () => {
  it("keeps SSO users on their own tab, loaded only when it is opened", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "list_auth_methods":
          return Promise.resolve([{ path: "userpass/", mount_type: "userpass" }]);
        case "list_policies":
          return Promise.resolve({ policies: [] });
        case "list_namespaces":
        case "list_namespaces_info":
          return Promise.resolve({ namespaces: [], details: {} });
        case "get_lockout_config":
        case "get_mfa_config":
          return Promise.resolve({ enabled: false });
        case "get_password_policy":
          return Promise.resolve({ min_length: 16 });
        case "list_users_info":
          return Promise.resolve({
            records: [
              {
                username: "alice",
                policies: [],
                disabled: false,
                locked: false,
                failed_login_count: 0,
                totp_mfa_enabled: false,
                totp_mount: "",
                totp_key: "",
                email: "",
                phone: "",
                registered_keys: 0,
                fido2_enabled: false,
              },
            ],
            total: 1,
            next: "",
          });
        case "list_sso_users":
          return Promise.resolve([FELIPE]);
        default:
          return Promise.resolve(null);
      }
    });
    renderWithProviders(<UsersPage />);

    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("Account Security")).toBeInTheDocument();
    expect(screen.queryByText(FELIPE.username)).toBeNull();
    expect(calls("list_sso_users")).toHaveLength(0);

    await userEvent.click(screen.getByRole("button", { name: "SSO Users" }));
    expect((await screen.findAllByText(FELIPE.username)).length).toBeGreaterThan(0);
    expect(screen.queryByText("alice")).toBeNull();
    expect(screen.queryByText("Account Security")).toBeNull();
    expect(screen.queryByRole("button", { name: "Create User" })).toBeNull();
  });
});
