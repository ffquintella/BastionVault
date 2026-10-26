import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";
import type { McpServerStatus } from "../lib/types";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
const handlers: Record<string, (e: { payload: unknown }) => void> = {};
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: (e: { payload: unknown }) => void) => {
    handlers[name] = cb;
    return Promise.resolve(() => {});
  },
  emit: () => Promise.resolve(),
}));

function renderWithProviders(ui: React.ReactNode) {
  return render(
    <MemoryRouter>
      <ToastProvider>{ui}</ToastProvider>
    </MemoryRouter>,
  );
}

const NOW = Math.floor(Date.now() / 1000);

const PAIRING = {
  id: "0123456789abcdef0123456789abcdef",
  client_name: "claude-desktop",
  client_version: "1.2.3",
  transport: "stdio",
  peer_uid: null,
  tool_allowlist: ["bv_kv_read_metadata", "bv_kv_list"],
  path_scope: ["secret/metadata/ai/*"],
  reveal_allowed: true,
  destructive_allowed: false,
  confirm_reveal: true,
  confirm_destructive: true,
  ttl_secs: 28_800,
  approved_at: NOW,
  expires_at: NOW + 86_400,
  last_used_at: NOW,
  expired: false,
};

const BINARY = "/Applications/BastionVault.app/Contents/MacOS/bastion-vault-gui";
const SOCKET = "/home/me/.config/bvault/mcp-gui.sock";

const SETUP = {
  binary_path: BINARY,
  socket_path: SOCKET,
  claude_code_command: `claude mcp add bastionvault -s user -- ${BINARY} --mcp-stdio`,
  claude_desktop_config: JSON.stringify(
    { mcpServers: { bastionvault: { command: BINARY, args: ["--mcp-stdio"] } } },
    null,
    2,
  ),
};

const OFF: McpServerStatus = {
  supported: true,
  enabled: false,
  running: false,
  socket_path: SOCKET,
  started_at: null,
  last_error: null,
};
const RUNNING: McpServerStatus = { ...OFF, enabled: true, running: true, started_at: NOW };

function calls(cmd: string) {
  return mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

describe("McpAssistantsPanel", () => {
  let pairings: unknown[];
  let status: McpServerStatus;
  let setEnabled: (args: { enabled: boolean }) => Promise<unknown>;

  beforeEach(() => {
    mockInvoke.mockReset();
    for (const k of Object.keys(handlers)) delete handlers[k];
    pairings = [PAIRING];
    status = OFF;
    setEnabled = ({ enabled }) => {
      status = enabled ? RUNNING : OFF;
      return Promise.resolve(status);
    };
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      switch (cmd) {
        case "mcp_list_pairings":
          return Promise.resolve(pairings);
        case "mcp_pairings_path":
          return Promise.resolve("/home/me/.config/bvault/mcp-pairings.json");
        case "mcp_server_status":
          return Promise.resolve(status);
        case "mcp_client_setup":
          return Promise.resolve(SETUP);
        case "mcp_server_set_enabled":
          return setEnabled(args as { enabled: boolean });
        case "mcp_revoke_pairing":
          pairings = [];
          return Promise.resolve();
        default:
          return Promise.resolve({});
      }
    });
  });

  async function mount() {
    const { McpAssistantsPanel } = await import("../components/McpAssistantsPanel");
    renderWithProviders(<McpAssistantsPanel />);
  }

  /** The switch, once the server's status has loaded and it is live. */
  async function switchButton(name: RegExp) {
    const button = await screen.findByRole("button", { name });
    await waitFor(() => expect(button).toBeEnabled());
    return button;
  }

  it("lists a paired assistant with its scope and switches", async () => {
    await mount();
    expect(await screen.findByText("claude-desktop 1.2.3")).toBeInTheDocument();
    expect(screen.getByText("secret/metadata/ai/*")).toBeInTheDocument();
    expect(screen.getByText("stdio")).toBeInTheDocument();
    expect(screen.getByText("allowed")).toBeInTheDocument();
    expect(screen.getByText(/mcp-pairings\.json/)).toBeInTheDocument();
  });

  it("shows where each assistant's calls run: the live token's namespace, a narrowing, or the sign-in's", async () => {
    pairings = [
      { ...PAIRING, id: "a".repeat(32), client_name: "narrowed-live", namespace: "dti/esi", token_namespace: "dti/esi" },
      { ...PAIRING, id: "b".repeat(32), client_name: "follows-live", namespace: null, token_namespace: "" },
      { ...PAIRING, id: "c".repeat(32), client_name: "narrowed-idle", namespace: "dti/ops", token_namespace: null },
      { ...PAIRING, id: "d".repeat(32), client_name: "idle" },
    ];
    await mount();
    expect(await screen.findByRole("columnheader", { name: "Namespace" })).toBeInTheDocument();
    const row = (name: string) => screen.getByText(`${name} 1.2.3`).closest("tr") as HTMLElement;
    await screen.findByText("narrowed-live 1.2.3");
    expect(row("narrowed-live")).toHaveTextContent("dti/esi");
    expect(row("narrowed-live")).toHaveTextContent("narrowed");
    expect(row("follows-live")).toHaveTextContent("root");
    expect(row("follows-live")).not.toHaveTextContent("narrowed");
    expect(row("narrowed-idle")).toHaveTextContent("dti/ops");
    expect(row("idle")).toHaveTextContent("follows your sign-in");
  });

  it("offers no button that approves a client: that happens only in the consent dialog", async () => {
    await mount();
    await screen.findByText("claude-desktop 1.2.3");
    expect(screen.getByText(/refused rather than waved through/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /pair|approve|allow/i })).not.toBeInTheDocument();
  });

  it("shows the Claude Code command and Claude Desktop config for this app's own binary, with no secret", async () => {
    await mount();
    expect(
      await screen.findByText(`claude mcp add bastionvault -s user -- ${BINARY} --mcp-stdio`),
    ).toBeInTheDocument();
    expect(screen.getByText(/"mcpServers"/)).toBeInTheDocument();
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/VAULT_ADDR|VAULT_TOKEN|"env"/);
  });

  it("turns the server on and shows it running on its socket", async () => {
    const user = userEvent.setup();
    await mount();
    await user.click(await switchButton(/turn on/i));
    await waitFor(() => expect(calls("mcp_server_set_enabled")).toHaveLength(1));
    expect(calls("mcp_server_set_enabled")[0][1]).toEqual({ enabled: true });
    expect(await screen.findByText("Running")).toBeInTheDocument();
    expect(screen.getByText(SOCKET)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /turn off/i })).toBeInTheDocument();
  });

  it("reports a refused start and stays off", async () => {
    const user = userEvent.setup();
    setEnabled = () =>
      Promise.reject({ message: "AI assistants cannot be served from a root session" });
    await mount();
    await user.click(await switchButton(/turn on/i));
    expect(await screen.findByText(/cannot be served from a root session/i)).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /turn on/i })).toBeInTheDocument();
  });

  it("turns a running server off", async () => {
    const user = userEvent.setup();
    status = RUNNING;
    await mount();
    await user.click(await switchButton(/turn off/i));
    await waitFor(() => expect(calls("mcp_server_set_enabled")[0][1]).toEqual({ enabled: false }));
    expect(await screen.findByText("Off")).toBeInTheDocument();
  });

  it("follows the server when it stops on its own, and says why", async () => {
    status = RUNNING;
    await mount();
    expect(await screen.findByText("Running")).toBeInTheDocument();
    await waitFor(() => expect(handlers["mcp-server-status"]).toBeDefined());
    act(() => {
      handlers["mcp-server-status"]({ payload: { ...RUNNING, running: false, last_error: "stopped: signed out" } });
    });
    expect(await screen.findByText("Off")).toBeInTheDocument();
    expect(screen.getByText("stopped: signed out")).toBeInTheDocument();
  });

  it("says when this platform cannot host the server", async () => {
    status = { ...OFF, supported: false };
    await mount();
    expect(await screen.findByText(/not supported on this platform/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /turn on/i })).not.toBeInTheDocument();
  });

  it("revokes a pairing only after confirmation, then refreshes the list", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText("claude-desktop 1.2.3");

    await user.click(screen.getByRole("button", { name: /^revoke$/i }));
    expect(calls("mcp_revoke_pairing")).toHaveLength(0);
    expect(screen.getByText(/cut off immediately and must be paired again/i)).toBeInTheDocument();

    await user.click(screen.getAllByRole("button", { name: /^revoke$/i }).pop()!);
    await waitFor(() => expect(calls("mcp_revoke_pairing")).toHaveLength(1));
    expect(calls("mcp_revoke_pairing")[0][1]).toEqual({ id: PAIRING.id });
    expect(await screen.findByText("No assistants paired")).toBeInTheDocument();
  });

  it("reports a vault-side revocation failure and still refreshes to the local truth", async () => {
    const user = userEvent.setup();
    const base = mockInvoke.getMockImplementation()!;
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      if (cmd === "mcp_revoke_pairing") {
        // The local record is gone, but the vault call failed.
        pairings = [];
        return Promise.reject({
          message: "the pairing is removed from this machine, but the vault did not revoke its tokens",
        });
      }
      return base(cmd, args);
    });
    await mount();
    await screen.findByText("claude-desktop 1.2.3");
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));
    await user.click(screen.getAllByRole("button", { name: /^revoke$/i }).pop()!);

    expect(await screen.findByText(/did not revoke its tokens/i)).toBeInTheDocument();
    expect(await screen.findByText("No assistants paired")).toBeInTheDocument();
  });

  it("marks an expired approval", async () => {
    pairings = [{ ...PAIRING, expired: true, expires_at: NOW - 10 }];
    await mount();
    expect(await screen.findByText("Expired")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is paired", async () => {
    pairings = [];
    await mount();
    expect(await screen.findByText("No assistants paired")).toBeInTheDocument();
    expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
  });

  it("never asks for, or renders, a token", async () => {
    await mount();
    await screen.findByText("claude-desktop 1.2.3");
    const read = new Set(["mcp_list_pairings", "mcp_pairings_path", "mcp_server_status", "mcp_client_setup"]);
    const commands = mockInvoke.mock.calls.map((c) => c[0] as string);
    expect(commands.every((c) => read.has(c))).toBe(true);
    expect(document.body.textContent ?? "").not.toMatch(/bearer\s+[a-f0-9]{16,}/i);
  });
});
