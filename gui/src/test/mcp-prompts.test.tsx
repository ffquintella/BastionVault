import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "../components/ui/Toast";
import { useAuthStore } from "../stores/authStore";

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

const DEFAULT_TOOLS = ["bv_whoami", "bv_kv_read_metadata", "bv_kv_list"];

const CATALOGUE = {
  hash: "abc",
  tools: [
    { name: "bv_whoami", description: "who am I", kind: "read" },
    { name: "bv_kv_read_metadata", description: "metadata", kind: "read" },
    { name: "bv_kv_list", description: "list", kind: "read" },
    { name: "bv_kv_read", description: "read a value", kind: "reveal" },
    { name: "bv_kv_delete", description: "delete", kind: "write" },
  ],
};

const PAIRING_PROMPT = {
  kind: "pairing",
  id: "mcp-prompt-1",
  client_name: "claude-code",
  client_version: "2.1.277",
  transport: "uds",
  peer_uid: 501,
  same_user: true,
  vault: "https://vault.example.com:8200",
  deadline_unix_ms: Date.now() + 180_000,
  default_tools: DEFAULT_TOOLS,
  default_ttl_secs: 28_800,
  max_ttl_secs: 86_400,
};

const CONFIRM_PROMPT = {
  kind: "confirm",
  id: "mcp-prompt-2",
  client_name: "claude-code",
  tool: "bv_kv_read",
  tool_description: "Read a KV secret's value",
  summary: "mount=secret path=ai/x",
  reveals: true,
  destructive: false,
  deadline_unix_ms: Date.now() + 90_000,
};

function calls(cmd: string) {
  return mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

describe("McpPromptHost", () => {
  let pending: unknown;
  let answer: (args: unknown) => Promise<unknown>;

  beforeEach(() => {
    mockInvoke.mockReset();
    for (const k of Object.keys(handlers)) delete handlers[k];
    useAuthStore.setState({ isAuthenticated: false });
    pending = null;
    answer = () => Promise.resolve();
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      switch (cmd) {
        case "mcp_prompt_pending":
          return Promise.resolve(pending);
        case "mcp_catalogue":
          return Promise.resolve(CATALOGUE);
        case "mcp_prompt_answer":
          return answer(args);
        case "mcp_server_autostart":
          return Promise.resolve({ running: true });
        default:
          return Promise.resolve({});
      }
    });
  });

  async function mount() {
    const { McpPromptHost } = await import("../components/McpPromptHost");
    render(
      <ToastProvider>
        <McpPromptHost />
      </ToastProvider>,
    );
    await waitFor(() => expect(handlers["mcp-prompt"]).toBeDefined());
  }

  function send(prompt: unknown) {
    act(() => handlers["mcp-prompt"]({ payload: prompt }));
  }

  it("shows nothing until a request arrives, and ignores a malformed one", async () => {
    await mount();
    expect(screen.queryByRole("button", { name: /approve|allow/i })).not.toBeInTheDocument();
    send({ kind: "bogus", id: "x" });
    send({});
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("asks for consent with the narrowest defaults and sends exactly the grant chosen", async () => {
    const user = userEvent.setup();
    await mount();
    send(PAIRING_PROMPT);

    expect(await screen.findByText("Approve an AI assistant?")).toBeInTheDocument();
    expect(screen.getByText("claude-code 2.1.277")).toBeInTheDocument();
    expect(screen.getByText("uid 501")).toBeInTheDocument();
    expect(screen.getByText("runs as you")).toBeInTheDocument();
    expect(screen.getByText("https://vault.example.com:8200")).toBeInTheDocument();
    // Read-only, non-revealing tools are preselected; nothing else is.
    await waitFor(() => expect(screen.getByLabelText("bv_kv_read")).toBeInTheDocument());
    for (const t of DEFAULT_TOOLS) expect(screen.getByLabelText(t)).toBeChecked();
    expect(screen.getByLabelText("bv_kv_read")).not.toBeChecked();
    expect(screen.getByLabelText("bv_kv_delete")).not.toBeChecked();
    expect(screen.getByLabelText("Allow revealing secret values")).not.toBeChecked();
    expect(screen.getByLabelText("Allow write and delete tools")).not.toBeChecked();
    // Confirmation per call is on, and only meaningful once its permission is.
    expect(screen.getByLabelText("Ask me before each reveal")).toBeChecked();
    expect(screen.getByLabelText("Ask me before each reveal")).toBeDisabled();

    // No scope, no approval.
    const approve = screen.getByRole("button", { name: /^approve$/i });
    expect(approve).toBeDisabled();
    await user.type(screen.getByLabelText(/path scope/i), "secret/metadata/ai/*");
    expect(approve).toBeEnabled();
    await user.click(approve);

    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({
      id: "mcp-prompt-1",
      answer: {
        kind: "pairing",
        approved: true,
        grant: {
          tool_allowlist: DEFAULT_TOOLS,
          path_scope: ["secret/metadata/ai/*"],
          reveal_allowed: false,
          destructive_allowed: false,
          confirm_reveal: false,
          confirm_destructive: false,
          ttl_secs: 28_800,
        },
      },
    });
    await waitFor(() => expect(screen.queryByText("Approve an AI assistant?")).not.toBeInTheDocument());
  });

  it("keeps per-call confirmation on when reveals are allowed", async () => {
    const user = userEvent.setup();
    await mount();
    send(PAIRING_PROMPT);
    await screen.findByText("Approve an AI assistant?");
    await user.click(screen.getByLabelText("Allow revealing secret values"));
    expect(screen.getByLabelText("Ask me before each reveal")).toBeEnabled();
    await user.click(screen.getByLabelText("bv_kv_read"));
    await user.type(screen.getByLabelText(/path scope/i), "secret/data/ai/*");
    await user.click(screen.getByRole("button", { name: /^approve$/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    const grant = (calls("mcp_prompt_answer")[0][1] as { answer: { grant: Record<string, unknown> } }).answer.grant;
    expect(grant.reveal_allowed).toBe(true);
    expect(grant.confirm_reveal).toBe(true);
    expect(grant.tool_allowlist).toContain("bv_kv_read");
  });

  it("denies explicitly, and closing the dialog is a denial too", async () => {
    const user = userEvent.setup();
    await mount();
    send(PAIRING_PROMPT);
    await user.click(await screen.findByRole("button", { name: /^deny$/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({
      id: "mcp-prompt-1",
      answer: { kind: "pairing", approved: false },
    });

    send({ ...PAIRING_PROMPT, id: "mcp-prompt-3" });
    await screen.findByText("Approve an AI assistant?");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(2));
    expect(calls("mcp_prompt_answer")[1][1]).toEqual({
      id: "mcp-prompt-3",
      answer: { kind: "pairing", approved: false },
    });
  });

  it("keeps the dialog open with the reason when the host refuses the grant", async () => {
    const user = userEvent.setup();
    answer = () => Promise.reject({ message: "a path scope entry is longer than 512 characters" });
    await mount();
    send(PAIRING_PROMPT);
    await screen.findByText("Approve an AI assistant?");
    await user.type(screen.getByLabelText(/path scope/i), "secret/*");
    await user.click(screen.getByRole("button", { name: /^approve$/i }));
    expect(await screen.findByText(/longer than 512 characters/)).toBeInTheDocument();
    expect(screen.getByText("Approve an AI assistant?")).toBeInTheDocument();
  });

  it("refuses a lifetime beyond the host's ceiling before sending anything", async () => {
    const user = userEvent.setup();
    await mount();
    send(PAIRING_PROMPT);
    await screen.findByText("Approve an AI assistant?");
    await user.type(screen.getByLabelText(/path scope/i), "secret/*");
    const ttl = screen.getByLabelText(/token lifetime/i);
    await user.clear(ttl);
    await user.type(ttl, "48");
    expect(screen.getByRole("button", { name: /^approve$/i })).toBeDisabled();
  });

  it("asks before a revealing call, shows what it touches, and defaults to deny", async () => {
    const user = userEvent.setup();
    await mount();
    send(CONFIRM_PROMPT);
    expect(await screen.findByText("Allow this AI-assistant call?")).toBeInTheDocument();
    expect(screen.getByText(/wants to reveal a secret value/)).toBeInTheDocument();
    expect(screen.getByText("bv_kv_read")).toBeInTheDocument();
    expect(screen.getByText("mount=secret path=ai/x")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^deny$/i })).toHaveFocus();

    await user.click(screen.getByRole("button", { name: /allow once/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({ id: "mcp-prompt-2", answer: { kind: "confirm", allow: true } });
  });

  it("closes a request the host withdrew (timed out or the server stopped)", async () => {
    await mount();
    send(CONFIRM_PROMPT);
    await screen.findByText("Allow this AI-assistant call?");
    act(() => handlers["mcp-prompt-closed"]({ payload: "some-other-id" }));
    expect(screen.getByText("Allow this AI-assistant call?")).toBeInTheDocument();
    act(() => handlers["mcp-prompt-closed"]({ payload: "mcp-prompt-2" }));
    await waitFor(() => expect(screen.queryByText("Allow this AI-assistant call?")).not.toBeInTheDocument());
    expect(calls("mcp_prompt_answer")).toHaveLength(0);
  });

  it("shows a request that was already waiting when the window mounted", async () => {
    pending = CONFIRM_PROMPT;
    await mount();
    expect(await screen.findByText("Allow this AI-assistant call?")).toBeInTheDocument();
  });

  it("starts the server once signed in, and not before", async () => {
    await mount();
    expect(calls("mcp_server_autostart")).toHaveLength(0);
    act(() => useAuthStore.setState({ isAuthenticated: true }));
    await waitFor(() => expect(calls("mcp_server_autostart")).toHaveLength(1));
  });
});
