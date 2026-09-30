import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { ToastProvider } from "../components/ui/Toast";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
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

function calls(cmd: string) {
  return mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

describe("McpAssistantsPanel", () => {
  let pairings: unknown[];

  beforeEach(() => {
    mockInvoke.mockReset();
    pairings = [PAIRING];
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "mcp_list_pairings":
          return Promise.resolve(pairings);
        case "mcp_pairings_path":
          return Promise.resolve("/home/me/.config/bvault/mcp-pairings.json");
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

  it("lists a paired assistant with its scope and switches", async () => {
    await mount();
    expect(await screen.findByText("claude-desktop 1.2.3")).toBeInTheDocument();
    expect(screen.getByText("secret/metadata/ai/*")).toBeInTheDocument();
    expect(screen.getByText("stdio")).toBeInTheDocument();
    expect(screen.getByText("allowed")).toBeInTheDocument();
    expect(screen.getByText(/mcp-pairings\.json/)).toBeInTheDocument();
  });

  it("explains that pairing needs a terminal instead of offering to do it", async () => {
    await mount();
    await screen.findByText("claude-desktop 1.2.3");
    expect(screen.getByText(/bvault mcp pair --client-name/)).toBeInTheDocument();
    expect(screen.getByText(/refused rather than waved through/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /pair|approve|allow/i })).not.toBeInTheDocument();
  });

  it("shows the client configuration snippets", async () => {
    await mount();
    await screen.findByText("claude-desktop 1.2.3");
    expect(screen.getByText(/"mcpServers"/)).toBeInTheDocument();
    expect(screen.getByText("claude mcp add bastionvault -- bvault mcp serve")).toBeInTheDocument();
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
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "mcp_list_pairings":
          return Promise.resolve(pairings);
        case "mcp_pairings_path":
          return Promise.resolve("/x/mcp-pairings.json");
        case "mcp_revoke_pairing":
          // The local record is gone, but the vault call failed.
          pairings = [];
          return Promise.reject({ message: "the pairing is removed from this machine, but the vault did not revoke its tokens" });
        default:
          return Promise.resolve({});
      }
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
    const commands = mockInvoke.mock.calls.map((c) => c[0] as string);
    expect(commands.every((c) => c === "mcp_list_pairings" || c === "mcp_pairings_path")).toBe(true);
    expect(document.body.textContent ?? "").not.toMatch(/bearer\s+[a-f0-9]{16,}/i);
  });
});
