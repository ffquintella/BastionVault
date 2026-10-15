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
    { name: "bv_resource_ssh_exec", description: "run one command", kind: "session" },
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

const SESSION_PROMPT = {
  kind: "confirm",
  id: "mcp-prompt-7",
  client_name: "claude-code",
  tool: "bv_resource_ssh_exec",
  tool_description: "Run one command on a resource",
  summary: "",
  reveals: false,
  destructive: true,
  deadline_unix_ms: Date.now() + 90_000,
  session: {
    resource: "web-01",
    profile: "agent-ops",
    protocol: "ssh",
    command: "journalctl -u nginx --since -1h\n\\u{0009}tail -n 200",
    command_bytes: 45,
    timeout_secs: null,
  },
  mfa: null,
};

const WEB_PROMPT = {
  ...SESSION_PROMPT,
  id: "mcp-prompt-9",
  tool: "bv_resource_web_fetch",
  tool_description: "Fetch one page of a web-application resource",
  destructive: false,
  session: {
    resource: "grafana",
    profile: "agent-api",
    protocol: "web",
    command: "",
    command_bytes: 0,
    method: "GET",
    path: "/api/health?verbose=1",
    path_bytes: 21,
    timeout_secs: null,
  },
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
          connect_allowed: false,
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

  it("offers brokered sessions in their own section, off by default, and warns when reveal is on too", async () => {
    const user = userEvent.setup();
    await mount();
    send(PAIRING_PROMPT);
    await screen.findByText("Approve an AI assistant?");
    expect(await screen.findByText(/Brokered sessions — lets this assistant open connections/)).toBeInTheDocument();
    const ssh = screen.getByLabelText("bv_resource_ssh_exec");
    expect(ssh).not.toBeChecked();
    expect(screen.getByText(/Every call is shown to you for approval/)).toBeInTheDocument();

    await user.click(ssh);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await user.click(screen.getByLabelText("Allow revealing secret values"));
    expect(screen.getByRole("alert")).toHaveTextContent(/read secret values and run commands on servers/);

    await user.type(screen.getByLabelText(/path scope/i), "resources/secrets/web-01/");
    await user.click(screen.getByRole("button", { name: /^approve$/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    const grant = (calls("mcp_prompt_answer")[0][1] as { answer: { grant: Record<string, unknown> } }).answer.grant;
    expect(grant.connect_allowed).toBe(true);
    expect(grant.tool_allowlist).toContain("bv_resource_ssh_exec");
    expect(grant).not.toHaveProperty("confirm_connect");
  });

  it("shows a session call field by field, every line of the command, and defaults to deny", async () => {
    const user = userEvent.setup();
    await mount();
    send(SESSION_PROMPT);
    expect(await screen.findByText("Run a command on web-01?")).toBeInTheDocument();
    expect(screen.getByText("agent-ops")).toBeInTheDocument();
    expect(screen.getByText("ssh")).toBeInTheDocument();
    const box = screen.getByTestId("mcp-session-command");
    expect(box).toHaveTextContent("journalctl -u nginx --since -1h");
    expect(box).toHaveTextContent("\\u{0009}tail -n 200");
    expect(screen.getByText("Command — 45 bytes, 2 lines")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^deny$/i })).toHaveFocus();
    expect(screen.queryByText(/complete MFA/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /run once/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({ id: "mcp-prompt-7", answer: { kind: "confirm", allow: true } });
  });

  it("shows a web fetch as one: the method, the whole path and the resource, deny first", async () => {
    const user = userEvent.setup();
    await mount();
    send(WEB_PROMPT);
    expect(await screen.findByText("Fetch a page from grafana?")).toBeInTheDocument();
    expect(screen.getByText("agent-api")).toBeInTheDocument();
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-session-path")).toHaveTextContent("GET /api/health?verbose=1");
    expect(screen.getByText("Request — 21 bytes of path")).toBeInTheDocument();
    expect(screen.queryByTestId("mcp-session-command")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^deny$/i })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: /^fetch once$/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({ id: "mcp-prompt-9", answer: { kind: "confirm", allow: true } });

    send({ ...WEB_PROMPT, id: "mcp-prompt-10", mfa: { methods: ["totp"] } });
    expect(await screen.findByRole("button", { name: /verify code and fetch once/i })).toBeDisabled();
    expect(screen.getByText(/is asking you to complete MFA to access/)).toHaveTextContent(
      "claude-code is asking you to complete MFA to access grafana (profile agent-api).",
    );
  });

  it("asks for the operator's own MFA on a gated profile and sends only the factor", async () => {
    const user = userEvent.setup();
    await mount();
    send({ ...SESSION_PROMPT, mfa: { methods: ["fido2", "totp"] } });
    await screen.findByText("Run a command on web-01?");
    expect(screen.getByText(/is asking you to complete MFA to access/)).toHaveTextContent(
      "claude-code is asking you to complete MFA to access web-01 (profile agent-ops).",
    );
    expect(screen.queryByRole("button", { name: /^run once$/i })).not.toBeInTheDocument();
    const verify = screen.getByRole("button", { name: /verify code and run once/i });
    expect(verify).toBeDisabled();
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    await user.click(verify);
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(1));
    expect(calls("mcp_prompt_answer")[0][1]).toEqual({
      id: "mcp-prompt-7",
      answer: { kind: "confirm", allow: true, mfa: { method: "totp", code: "123456" } },
    });

    send({ ...SESSION_PROMPT, id: "mcp-prompt-8", mfa: { methods: ["fido2"] } });
    await user.click(await screen.findByRole("button", { name: /use security key and run/i }));
    await waitFor(() => expect(calls("mcp_prompt_answer")).toHaveLength(2));
    expect(calls("mcp_prompt_answer")[1][1]).toEqual({
      id: "mcp-prompt-8",
      answer: { kind: "confirm", allow: true, mfa: { method: "fido2" } },
    });
  });

  it("reports a refused factor: the call is denied and the dialog closes", async () => {
    const user = userEvent.setup();
    answer = () => Promise.reject({ message: "MFA was not accepted, so the call was refused: invalid TOTP code" });
    await mount();
    send({ ...SESSION_PROMPT, mfa: { methods: ["totp"] } });
    await screen.findByText("Run a command on web-01?");
    await user.type(screen.getByLabelText("Authenticator code"), "000000");
    await user.click(screen.getByRole("button", { name: /verify code and run once/i }));
    expect(await screen.findByText(/invalid TOTP code/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("Run a command on web-01?")).not.toBeInTheDocument());
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
