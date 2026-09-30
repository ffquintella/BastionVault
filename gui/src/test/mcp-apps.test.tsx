import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
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
// Isolate the page from the Layout chrome; only McpAppsPage's own logic is under test.
vi.mock("../components/Layout", () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

function renderWithProviders(ui: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={["/mcp-apps"]}>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  );
}

const NOW = Math.floor(Date.now() / 1000);

const APP = {
  name: "ci-secrets-reader",
  approle_role: "reader-role",
  entity_id: "",
  description: "CI runner",
  tool_allowlist: ["bv_kv_read_metadata", "bv_kv_list"],
  path_scope: ["secret/metadata/ai/*"],
  reveal_allowed: false,
  destructive_allowed: false,
  ttl_secs: 3600,
  machine_waiver: null,
  created_at: NOW,
  updated_at: NOW,
};

const WAIVED_APP = {
  ...APP,
  name: "legacy-batch",
  machine_waiver: { reason: "no agent", granted_by: "root", granted_at: NOW, expires_at: NOW + 86_400 },
};

const CATALOGUE = {
  hash: "a".repeat(64),
  tools: [
    { name: "bv_kv_read_metadata", description: "Read metadata", kind: "read" },
    { name: "bv_kv_list", description: "List keys", kind: "read" },
    { name: "bv_kv_read", description: "Read a secret", kind: "reveal" },
    { name: "bv_kv_write", description: "Write a secret", kind: "write" },
  ],
};

const TOKEN = {
  accessor: "f".repeat(64),
  kind: "app",
  app: "ci-secrets-reader",
  client_name: "",
  client_version: "",
  issued_at: NOW,
  expires_at: NOW + 3600,
};

function calls(cmd: string) {
  return mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

describe("McpAppsPage", () => {
  let config: { catalogue_pin: string | null };

  beforeEach(() => {
    mockInvoke.mockReset();
    config = { catalogue_pin: null };
    useAuthStore.setState({ token: "t", policies: ["root"], isAuthenticated: true });
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "mcp_list_apps":
          return Promise.resolve([APP, WAIVED_APP]);
        case "mcp_list_tokens":
          return Promise.resolve([TOKEN]);
        case "mcp_read_config":
          return Promise.resolve({
            default_ttl_secs: 3600,
            max_ttl_secs: 86400,
            waiver_max_days: 90,
            catalogue_pin: config.catalogue_pin,
          });
        case "mcp_catalogue":
          return Promise.resolve(CATALOGUE);
        default:
          return Promise.resolve({});
      }
    });
  });

  async function mount() {
    const { McpAppsPage } = await import("../routes/McpAppsPage");
    renderWithProviders(<McpAppsPage />);
    await waitFor(() => expect(screen.getByText("ci-secrets-reader")).toBeInTheDocument());
  }

  it("lists apps with their machine-identity state", async () => {
    await mount();
    expect(screen.getByText("legacy-batch")).toBeInTheDocument();
    expect(screen.getByText("Attested")).toBeInTheDocument();
    expect(screen.getByText(/^Waived until/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /revoke waiver/i })).toBeInTheDocument();
  });

  it("creates an app with the chosen tools, scope and switches", async () => {
    const user = userEvent.setup();
    await mount();

    await user.click(screen.getAllByRole("button", { name: /^new app$/i })[0]);
    await user.type(screen.getByLabelText("Name"), "new-reader");
    await user.type(screen.getByLabelText("AppID role"), "reader-role");
    await user.click(screen.getByRole("checkbox", { name: "bv_kv_read_metadata" }));
    await user.click(screen.getByRole("checkbox", { name: "bv_kv_read" }));
    await user.type(screen.getByLabelText(/path scope/i), "secret/metadata/ai/*{enter}transit/encrypt/ai-*");
    await user.click(screen.getByRole("checkbox", { name: /allow revealing secret values/i }));
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() => expect(calls("mcp_write_app")).toHaveLength(1));
    expect(calls("mcp_write_app")[0][1]).toEqual({
      name: "new-reader",
      approleRole: "reader-role",
      description: "",
      toolAllowlist: ["bv_kv_read_metadata", "bv_kv_read"],
      pathScope: ["secret/metadata/ai/*", "transit/encrypt/ai-*"],
      revealAllowed: true,
      destructiveAllowed: false,
      ttlSecs: 3600,
    });
  });

  it("defaults a new app to no tools, no scope, no reveal and no writes", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getAllByRole("button", { name: /^new app$/i })[0]);
    await user.type(screen.getByLabelText("Name"), "locked-down");
    await user.type(screen.getByLabelText("AppID role"), "r");
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() => expect(calls("mcp_write_app")).toHaveLength(1));
    const sent = calls("mcp_write_app")[0][1];
    expect(sent.toolAllowlist).toEqual([]);
    expect(sent.pathScope).toEqual([]);
    expect(sent.revealAllowed).toBe(false);
    expect(sent.destructiveAllowed).toBe(false);
  });

  it("refuses a malformed name or missing role without calling the vault", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getAllByRole("button", { name: /^new app$/i })[0]);

    await user.type(screen.getByLabelText("Name"), "Bad Name!");
    await user.type(screen.getByLabelText("AppID role"), "r");
    await user.click(screen.getByRole("button", { name: /^create$/i }));
    expect(await screen.findByText(/lowercase letters, digits and dashes/i)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "fine-name");
    await user.clear(screen.getByLabelText("AppID role"));
    await user.click(screen.getByRole("button", { name: /^create$/i }));
    expect(await screen.findByText(/AppID role is required/i)).toBeInTheDocument();

    expect(calls("mcp_write_app")).toHaveLength(0);
  });

  it("refuses an out-of-range token lifetime", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getAllByRole("button", { name: /^new app$/i })[0]);
    await user.type(screen.getByLabelText("Name"), "x");
    await user.type(screen.getByLabelText("AppID role"), "r");
    await user.clear(screen.getByLabelText(/token lifetime/i));
    await user.type(screen.getByLabelText(/token lifetime/i), "999999");
    await user.click(screen.getByRole("button", { name: /^create$/i }));
    expect(await screen.findByText(/lifetime must be between/i)).toBeInTheDocument();
    expect(calls("mcp_write_app")).toHaveLength(0);
  });

  it("editing keeps the name fixed and sends the existing record's fields", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getAllByRole("button", { name: /^edit$/i })[0]);
    expect(screen.getByLabelText("Name")).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "bv_kv_list" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(calls("mcp_write_app")).toHaveLength(1));
    const sent = calls("mcp_write_app")[0][1];
    expect(sent.name).toBe("ci-secrets-reader");
    expect(sent.toolAllowlist).toEqual(["bv_kv_read_metadata", "bv_kv_list"]);
    expect(sent.pathScope).toEqual(["secret/metadata/ai/*"]);
  });

  it("a waiver needs a reason and a bounded expiry", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByRole("button", { name: /waive attestation/i }));

    await user.click(screen.getByRole("button", { name: /^grant waiver$/i }));
    expect(await screen.findByText(/reason is required/i)).toBeInTheDocument();
    expect(calls("mcp_grant_waiver")).toHaveLength(0);

    await user.type(screen.getByLabelText(/reason/i), "no agent on this runner");
    await user.clear(screen.getByLabelText(/expires in/i));
    await user.type(screen.getByLabelText(/expires in/i), "365");
    await user.click(screen.getByRole("button", { name: /^grant waiver$/i }));
    expect(await screen.findByText(/between 1 and 90 days/i)).toBeInTheDocument();
    expect(calls("mcp_grant_waiver")).toHaveLength(0);

    await user.clear(screen.getByLabelText(/expires in/i));
    await user.type(screen.getByLabelText(/expires in/i), "14");
    await user.click(screen.getByRole("button", { name: /^grant waiver$/i }));
    await waitFor(() => expect(calls("mcp_grant_waiver")).toHaveLength(1));
    expect(calls("mcp_grant_waiver")[0][1]).toEqual({
      name: "ci-secrets-reader",
      reason: "no agent on this runner",
      expiresInDays: 14,
    });
  });

  it("revokes a waiver only after confirmation", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByRole("button", { name: /revoke waiver/i }));
    expect(calls("mcp_revoke_waiver")).toHaveLength(0);
    const confirm = screen.getAllByRole("button", { name: /^revoke waiver$/i }).pop()!;
    await user.click(confirm);
    await waitFor(() => expect(calls("mcp_revoke_waiver")).toHaveLength(1));
    expect(calls("mcp_revoke_waiver")[0][1]).toEqual({ name: "legacy-batch" });
  });

  it("deletes an app only after confirmation", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getAllByRole("button", { name: /^delete$/i })[0]);
    expect(calls("mcp_delete_app")).toHaveLength(0);
    expect(screen.getByText(/every token it has been issued is revoked/i)).toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: /^delete$/i }).pop()!);
    await waitFor(() => expect(calls("mcp_delete_app")).toHaveLength(1));
    expect(calls("mcp_delete_app")[0][1]).toEqual({ name: "ci-secrets-reader" });
  });

  it("lists active tokens and revokes one by accessor", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByText(/^Tokens/));
    expect(await screen.findByText("f".repeat(64))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));
    await user.click(screen.getAllByRole("button", { name: /^revoke$/i }).pop()!);
    await waitFor(() => expect(calls("mcp_revoke_token")).toHaveLength(1));
    expect(calls("mcp_revoke_token")[0][1]).toEqual({ accessor: "f".repeat(64) });
  });

  it("shows the catalogue hash and pins it", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByText(/^Catalogue$/));
    expect(await screen.findByTestId("catalogue-hash")).toHaveTextContent("a".repeat(64));
    expect(screen.getByText("Not pinned")).toBeInTheDocument();
    expect(screen.getByText("bv_kv_write")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /pin this hash/i }));
    await waitFor(() => expect(calls("mcp_write_config")).toHaveLength(1));
    expect(calls("mcp_write_config")[0][1]).toMatchObject({ cataloguePin: "a".repeat(64) });
  });

  it("flags a pin that no longer matches this build", async () => {
    config.catalogue_pin = "b".repeat(64);
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByText(/^Catalogue$/));
    expect(await screen.findByText(/pinned to a different catalogue/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /clear pin/i }));
    await waitFor(() => expect(calls("mcp_write_config")).toHaveLength(1));
    expect(calls("mcp_write_config")[0][1]).toMatchObject({ cataloguePin: "" });
  });

  it("settings refuse a default lifetime above the maximum", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(screen.getByText(/^Settings$/));
    await user.clear(await screen.findByLabelText(/default token lifetime/i));
    await user.type(screen.getByLabelText(/default token lifetime/i), "90000");
    await user.click(screen.getByRole("button", { name: /save settings/i }));
    expect(await screen.findByText(/cannot exceed the maximum/i)).toBeInTheDocument();
    expect(calls("mcp_write_config")).toHaveLength(0);
  });

  it("shows an empty state that explains what an app is", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "mcp_list_apps" || cmd === "mcp_list_tokens") return Promise.resolve([]);
      if (cmd === "mcp_read_config") {
        return Promise.resolve({ default_ttl_secs: 3600, max_ttl_secs: 86400, waiver_max_days: 90, catalogue_pin: null });
      }
      if (cmd === "mcp_catalogue") return Promise.resolve(CATALOGUE);
      return Promise.resolve({});
    });
    const { McpAppsPage } = await import("../routes/McpAppsPage");
    renderWithProviders(<McpAppsPage />);
    expect(await screen.findByText(/works nowhere else/i)).toBeInTheDocument();
    expect(screen.getByText("No MCP apps")).toBeInTheDocument();
    expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
  });
});
