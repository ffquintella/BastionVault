import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import { ProfilePage } from "../routes/ProfilePage";
import * as api from "../lib/api";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: () => Promise.resolve() }));
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

/** A userpass operator with a password, contact details, and a stored
 *  Windows RDP password (presence only — the plaintext never leaves Rust). */
function profile(overrides: Record<string, unknown> = {}) {
  return {
    username: "alice",
    display_name: "alice",
    entity_id: "ent-1",
    auth_mount: "auth/pass/",
    auth_method: "userpass",
    policies: ["standard-user", "default"],
    email: "alice@example.com",
    phone: "+55 21 1234-5678",
    disabled: false,
    fido2_enabled: false,
    totp_mfa_enabled: false,
    can_change_password: true,
    can_edit_contact: true,
    can_edit_default_account: true,
    default_account: {
      mount: "userpass/",
      name: "alice",
      linux: "alice-svc",
      macos: "",
      windows: "CORP\\alice",
      has_windows_password: true,
      updated_at: "2026-07-01T00:00:00Z",
    },
    ...overrides,
  };
}

const PASSWORD_POLICY = {
  min_length: 8,
  require_lowercase: false,
  require_uppercase: false,
  require_digits: false,
  require_symbols: false,
};

function mockBackend(p: Record<string, unknown> = profile()) {
  mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "get_my_profile":
        return Promise.resolve(p);
      case "get_password_policy":
        return Promise.resolve(PASSWORD_POLICY);
      case "change_my_password":
      case "update_my_contact":
      case "set_my_default_account":
        return Promise.resolve(undefined);
      default:
        return Promise.reject(new Error(`unmocked: ${cmd}`));
    }
  });
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <ProfilePage />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("self-service profile API wrappers", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("changeMyPassword sends both passwords and no username", async () => {
    await api.changeMyPassword("old-one", "new-one-1");
    expect(mockInvoke).toHaveBeenCalledWith("change_my_password", {
      currentPassword: "old-one",
      newPassword: "new-one-1",
    });
  });

  it("updateMyContact omits fields the caller left undefined", async () => {
    await api.updateMyContact(undefined, "+55 21 0000-0000");
    expect(mockInvoke).toHaveBeenCalledWith("update_my_contact", {
      email: undefined,
      phone: "+55 21 0000-0000",
    });
  });

  it("setMyDefaultAccount forwards every field, including a cleared password", async () => {
    await api.setMyDefaultAccount("alice-svc", "", "CORP\\alice", "");
    expect(mockInvoke).toHaveBeenCalledWith("set_my_default_account", {
      linux: "alice-svc",
      macos: "",
      windows: "CORP\\alice",
      windowsPassword: "",
    });
  });
});

describe("ProfilePage", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockBackend();
  });

  it("renders the operator's own identity and current values", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    expect(screen.getByDisplayValue("alice@example.com")).toBeInTheDocument();
    expect(screen.getByDisplayValue("alice-svc")).toBeInTheDocument();
    expect(screen.getByDisplayValue("CORP\\alice")).toBeInTheDocument();
    // The real issuing mount, not the `userpass/` literal the token stamps.
    expect(screen.getByText("auth/pass/")).toBeInTheDocument();
  });

  it("keeps Save disabled until a field actually changes", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() =>
      expect(screen.getByDisplayValue("alice@example.com")).toBeInTheDocument(),
    );
    const saveButtons = screen.getAllByRole("button", { name: "Save" });
    expect(saveButtons[0]).toBeDisabled();

    await user.clear(screen.getByDisplayValue("alice@example.com"));
    await user.type(screen.getByLabelText("Email"), "alice@fgv.br");
    expect(screen.getAllByRole("button", { name: "Save" })[0]).toBeEnabled();
  });

  it("saves contact details through the caller-scoped command", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() =>
      expect(screen.getByDisplayValue("alice@example.com")).toBeInTheDocument(),
    );
    await user.clear(screen.getByLabelText("Email"));
    await user.type(screen.getByLabelText("Email"), "alice@fgv.br");
    await user.click(screen.getAllByRole("button", { name: "Save" })[0]);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("update_my_contact", {
        email: "alice@fgv.br",
        phone: "+55 21 1234-5678",
      }),
    );
  });

  it("requires the current password and a matching confirmation", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Current password")).toBeInTheDocument(),
    );
    const change = screen.getByRole("button", { name: "Change password" });
    expect(change).toBeDisabled();

    // New + confirm alone is not enough — the current password gates it.
    await user.type(screen.getByLabelText("New password"), "new-password-1");
    await user.type(screen.getByLabelText("Confirm new password"), "new-password-1");
    expect(change).toBeDisabled();

    await user.type(screen.getByLabelText("Current password"), "old-password-1");
    expect(change).toBeEnabled();

    await user.click(change);
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("change_my_password", {
        currentPassword: "old-password-1",
        newPassword: "new-password-1",
      }),
    );
  });

  it("blocks a mismatched confirmation", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Current password")).toBeInTheDocument(),
    );
    await user.type(screen.getByLabelText("Current password"), "old-password-1");
    await user.type(screen.getByLabelText("New password"), "new-password-1");
    await user.type(screen.getByLabelText("Confirm new password"), "new-password-2");
    expect(screen.getByText("Does not match")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change password" })).toBeDisabled();
  });

  it("omits the Windows password when the operator did not retype it", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByDisplayValue("alice-svc")).toBeInTheDocument());

    await user.clear(screen.getByLabelText("Linux / Unix"));
    await user.type(screen.getByLabelText("Linux / Unix"), "alice-ops");
    // The default-account card's Save is the last one on the page.
    const saves = screen.getAllByRole("button", { name: "Save" });
    await user.click(saves[saves.length - 1]);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("set_my_default_account", {
        linux: "alice-ops",
        macos: "",
        windows: "CORP\\alice",
        // undefined ⇒ the server preserves the stored password.
        windowsPassword: undefined,
      }),
    );
  });

  it("sends an empty password when the operator asks to clear it", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByDisplayValue("alice-svc")).toBeInTheDocument());

    await user.click(
      screen.getByLabelText(/Clear the stored Windows password/),
    );
    const saves = screen.getAllByRole("button", { name: "Save" });
    await user.click(saves[saves.length - 1]);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("set_my_default_account", {
        linux: "alice-svc",
        macos: "",
        windows: "CORP\\alice",
        windowsPassword: "",
      }),
    );
  });

  it("explains why a FIDO2-only account has no password section", async () => {
    mockBackend(
      profile({ fido2_enabled: true, can_change_password: false }),
    );
    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText(/signs in with a FIDO2 security key/),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
  });

  it("explains a non-password login instead of offering a dead form", async () => {
    mockBackend(
      profile({
        username: "",
        auth_mount: "",
        auth_method: "",
        can_change_password: false,
        can_edit_contact: false,
      }),
    );
    renderPage();
    await waitFor(() =>
      expect(
        screen.getByText(/not opened with a username and password/),
      ).toBeInTheDocument(),
    );
  });
});
