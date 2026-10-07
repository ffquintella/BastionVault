/**
 * The host-rendered credential-provider account picker and the Connect
 * sequence around it (features/self-accounts.md §6, T103 Phase 4):
 * rendering, the empty state, single-candidate preselection, the keyboard,
 * text-only rendering of hostile strings, and the order
 * candidates → picker → MFA → open (a cancelled picker never reaches MFA).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";

import type { ProviderCandidate, ProviderCandidates } from "../lib/api";
import { ProviderAccountPicker, useProviderAccountPicker, type PendingProviderPick } from "../components/ProviderAccountPicker";
import { useConnectMfa } from "../components/ConnectMfaPrompt";
import { connectProfile } from "../lib/connectFlow";
import type { ConnectionProfile } from "../lib/types";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

const NOW = Date.parse("2026-10-07T12:00:00Z");

function candidate(extra: Partial<ProviderCandidate> = {}): ProviderCandidate {
  return {
    id: "sa_1",
    label: "Domain admin",
    username: "felipe.adm",
    domain: "CORP",
    secret_kind: "password",
    has_totp: false,
    last_used_at: "2026-10-04T12:00:00Z",
    ...extra,
  };
}

function data(candidates: ProviderCandidate[], extra: Partial<ProviderCandidates> = {}): ProviderCandidates {
  return {
    provider: "self-accounts",
    display_name: "Self-account",
    protocol: "rdp",
    resource_type: "server",
    os_type: "windows",
    target: { kind: "host", host: "dc01.corp.example.com", port: 3389 },
    candidates,
    hidden: 0,
    ...extra,
  };
}

function renderPicker(d: ProviderCandidates, accountsLink?: (p: string) => (() => void) | null) {
  const resolve = vi.fn();
  const pending: PendingProviderPick = { resourceName: "dc01", profileName: "Self-account", data: d, resolve };
  const view = render(<ProviderAccountPicker pending={pending} accountsLink={accountsLink} now={NOW} />);
  return { resolve, ...view };
}

const connectButton = () => screen.getByRole("button", { name: "Connect" });

describe("ProviderAccountPicker", () => {
  it("shows the server's target and each account's metadata", () => {
    renderPicker(
      data([
        candidate(),
        candidate({ id: "sa_2", label: "Web", username: "fw", domain: null, secret_kind: "ssh-key", has_totp: true, last_used_at: null }),
      ]),
    );
    expect(screen.getByTestId("provider-picker-target")).toHaveTextContent("dc01.corp.example.com:3389");
    expect(screen.getByText("Connecting to")).toBeInTheDocument();
    expect(screen.getByText("Domain admin")).toBeInTheDocument();
    expect(screen.getByText("CORP\\felipe.adm")).toBeInTheDocument();
    expect(screen.getByText("Password")).toBeInTheDocument();
    expect(screen.getByText("Used 3 days ago")).toBeInTheDocument();
    expect(screen.getByText("Key")).toBeInTheDocument();
    expect(screen.getByText("TOTP")).toBeInTheDocument();
    expect(screen.getByText("Never used")).toBeInTheDocument();
    expect(screen.getAllByRole("option")).toHaveLength(2);
  });

  it("preselects a single candidate", async () => {
    const { resolve } = renderPicker(data([candidate()]));
    await waitFor(() => expect(screen.getByRole("option")).toHaveAttribute("aria-selected", "true"));
    expect(connectButton()).toBeEnabled();
    await userEvent.click(connectButton());
    expect(resolve).toHaveBeenCalledWith("sa_1");
  });

  it("selects nothing among several until the operator does; arrows and Enter work", async () => {
    const { resolve } = renderPicker(
      data([candidate(), candidate({ id: "sa_2", label: "Second" }), candidate({ id: "sa_3", label: "Third" })]),
    );
    const list = screen.getByRole("listbox");
    expect(connectButton()).toBeDisabled();
    fireEvent.keyDown(list, { key: "Enter" });
    expect(resolve).not.toHaveBeenCalled();

    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(list, { key: "ArrowDown" }); // clamps at the last
    fireEvent.keyDown(list, { key: "ArrowUp" });
    const options = screen.getAllByRole("option");
    expect(options[1]).toHaveAttribute("aria-selected", "true");
    expect(list).toHaveAttribute("aria-activedescendant", "provider-account-1");
    fireEvent.keyDown(list, { key: "Enter" });
    expect(resolve).toHaveBeenCalledWith("sa_2");
  });

  it("selects by click, connects on double-click, and cancels on Escape", async () => {
    const { resolve } = renderPicker(data([candidate(), candidate({ id: "sa_2", label: "Second" })]));
    await userEvent.click(screen.getByText("Second"));
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    await userEvent.dblClick(screen.getByText("Domain admin"));
    expect(resolve).toHaveBeenLastCalledWith("sa_1");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(resolve).toHaveBeenLastCalledWith(null);
  });

  it("explains an empty list, keeps Connect disabled and links to the provider's page", async () => {
    const open = vi.fn();
    const { resolve } = renderPicker(data([]), (p) => (p === "self-accounts" ? open : null));
    expect(screen.getByRole("status")).toHaveTextContent(
      "You have no self-accounts for server (Windows) on this target.",
    );
    expect(connectButton()).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Add a self-account" }));
    expect(resolve).toHaveBeenCalledWith(null);
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("offers no link where the provider registers no page (or the window shows none)", () => {
    renderPicker(data([]), () => null);
    expect(screen.queryByRole("button", { name: /Add a/ })).not.toBeInTheDocument();
    renderPicker(data([]));
    expect(screen.queryByRole("button", { name: /Add a/ })).not.toBeInTheDocument();
  });

  it("renders hostile metadata as text, never as markup", () => {
    const hostile = '<img src=x onerror="alert(1)"><b>admin</b>';
    const { container } = renderPicker(
      data([candidate({ label: hostile, username: "<script>x</script>", domain: "<i>CORP</i>" })], {
        display_name: "<b>Evil</b>",
        resource_type: "<u>server</u>",
      }),
    );
    expect(container.ownerDocument.querySelector("img, script, b, i, u")).toBeNull();
    expect(screen.getByText(hostile)).toBeInTheDocument();
    expect(screen.getByText("<i>CORP</i>\\<script>x</script>")).toBeInTheDocument();
    // Long values are truncated by CSS, with the full text in the title.
    expect(screen.getByText(hostile)).toHaveAttribute("title", hostile);
    expect(screen.getByText(hostile).className).toContain("truncate");
  });

  it("says how many accounts the host withheld", () => {
    renderPicker(data([candidate()], { hidden: 2 }));
    expect(screen.getByText(/2 accounts were not shown/)).toBeInTheDocument();
  });

  it("marks a first use on this host, and cautions only when that account is selected", async () => {
    renderPicker(
      data([
        candidate({ first_use_on_target: false, last_used_on_target: "2026-10-06T12:00:00Z" }),
        candidate({ id: "sa_2", label: "Fresh", first_use_on_target: true, last_used_on_target: null }),
      ]),
    );
    const badges = screen.getAllByText("First use on this host");
    expect(badges).toHaveLength(1);
    expect(screen.getAllByRole("option")[1]).toContainElement(badges[0]);
    // The familiar account is preselected: no caution.
    await waitFor(() => expect(screen.getAllByRole("option")[0]).toHaveAttribute("aria-selected", "true"));
    expect(screen.queryByTestId("provider-first-use-hint")).not.toBeInTheDocument();
    // Picking the unfamiliar one shows the one-line caution with the target.
    await userEvent.click(screen.getByText("Fresh"));
    expect(screen.getByTestId("provider-first-use-hint")).toHaveTextContent(
      "You have not used this account on this host before. Check that dc01.corp.example.com:3389 is where you mean to sign in.",
    );
  });

  it("says site for a web target, and shows nothing for a provider that does not report it", () => {
    renderPicker(
      data([candidate({ first_use_on_target: true }), candidate({ id: "sa_2", label: "Old provider" })], {
        protocol: "web",
        target: { kind: "origins", origins: ["https://fw01.example.com"] },
      }),
    );
    expect(screen.getAllByText("First use on this site")).toHaveLength(1);
    expect(screen.queryByText("First use on this host")).not.toBeInTheDocument();
  });

  it("preselects the account last used on this target, keeps the order, and arrows move from it", async () => {
    const { resolve } = renderPicker(
      data([
        candidate({ id: "sa_1", label: "Alpha", last_used_on_target: "2026-09-01T00:00:00Z" }),
        candidate({ id: "sa_2", label: "Bravo", last_used_on_target: "2026-10-06T08:00:00Z" }),
        candidate({ id: "sa_3", label: "Charlie", last_used_on_target: null, first_use_on_target: true }),
        candidate({ id: "sa_4", label: "Delta", last_used_on_target: "not a time" }),
      ]),
    );
    const options = screen.getAllByRole("option");
    expect(options.map((o) => o.textContent?.match(/Alpha|Bravo|Charlie|Delta/)?.[0])).toEqual([
      "Alpha",
      "Bravo",
      "Charlie",
      "Delta",
    ]);
    await waitFor(() => expect(options[1]).toHaveAttribute("aria-selected", "true"));
    expect(connectButton()).toBeEnabled();
    const list = screen.getByRole("listbox");
    fireEvent.keyDown(list, { key: "ArrowDown" });
    expect(screen.getAllByRole("option")[2]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(list, { key: "ArrowUp" });
    fireEvent.keyDown(list, { key: "Enter" });
    expect(resolve).toHaveBeenCalledWith("sa_2");
  });

  it("shows a web target as its start origin", () => {
    renderPicker(
      data([candidate()], {
        protocol: "web",
        target: { kind: "origins", origins: ["https://fw01.example.com", "https://sso.example.com"] },
      }),
    );
    expect(screen.getByTestId("provider-picker-target")).toHaveTextContent("https://fw01.example.com (+1 more origin)");
  });
});

// ── The Connect sequence ──────────────────────────────────────────────

const PROVIDER_PROFILE: ConnectionProfile = {
  id: "p_sa",
  name: "Self-account",
  protocol: "rdp",
  require_mfa: true,
  credential_source: { kind: "provider", provider: "self-accounts" },
};

function Harness({ profile }: { profile: ConnectionProfile }) {
  const { gateConnect, mfaPrompt } = useConnectMfa();
  const { pickProviderAccount, providerPicker } = useProviderAccountPicker();
  const [result, setResult] = useState("");
  return (
    <>
      <button
        type="button"
        onClick={() =>
          connectProfile({ pickProviderAccount, gateConnect }, profile, {
            resource_name: "dc01",
            profile_id: profile.id,
          }).then(setResult, (e: Error) => setResult(`error: ${e.message}`))
        }
      >
        go
      </button>
      <div data-testid="result">{result}</div>
      {providerPicker}
      {mfaPrompt}
    </>
  );
}

function backend(overrides: Record<string, (args: unknown) => Promise<unknown>> = {}) {
  mockInvoke.mockImplementation((cmd: string, args: unknown) => {
    if (overrides[cmd]) return overrides[cmd](args);
    switch (cmd) {
      case "connect_provider_candidates":
        return Promise.resolve(data([candidate()]));
      case "connect_mfa_begin":
        return Promise.resolve({ required: true, methods: ["totp"] });
      case "connect_mfa_verify_totp":
        return Promise.resolve({ connect_ticket: "tkt_1", expires_at: "", method: "totp" });
      case "session_open_rdp":
      case "session_open_ssh":
      case "session_open_web":
        return Promise.resolve({ token: "t" });
      default:
        return Promise.reject(new Error(`unmocked: ${cmd}`));
    }
  });
}

const commands = () => mockInvoke.mock.calls.map((c) => c[0] as string);

describe("Connect with a provider profile", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("runs candidates, then the picker, then MFA, then the open with the picked account", async () => {
    backend();
    render(<Harness profile={PROVIDER_PROFILE} />);
    await userEvent.click(screen.getByText("go"));

    // The picker is up and MFA has not been asked yet.
    await screen.findByText("Choose an account");
    expect(commands()).toEqual(["connect_provider_candidates"]);
    expect(mockInvoke).toHaveBeenCalledWith("connect_provider_candidates", { resourceName: "dc01", profileId: "p_sa" });

    await userEvent.click(screen.getByRole("button", { name: "Connect" }));
    // The MFA prompt follows the pick.
    await userEvent.type(await screen.findByLabelText("Authenticator code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify and connect" }));

    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent("opened"));
    expect(commands()).toEqual([
      "connect_provider_candidates",
      "connect_mfa_begin",
      "connect_mfa_verify_totp",
      "session_open_rdp",
    ]);
    expect(mockInvoke).toHaveBeenLastCalledWith("session_open_rdp", {
      request: expect.objectContaining({
        resource_name: "dc01",
        profile_id: "p_sa",
        provider_account_id: "sa_1",
        connect_ticket: "tkt_1",
      }),
    });
  });

  it("never runs the MFA ceremony when the picker is cancelled", async () => {
    backend();
    render(<Harness profile={PROVIDER_PROFILE} />);
    await userEvent.click(screen.getByText("go"));
    await screen.findByText("Choose an account");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent("cancelled"));
    expect(commands()).toEqual(["connect_provider_candidates"]);
  });

  it("never opens the picker or MFA when the account list is refused, and says why", async () => {
    backend({
      connect_provider_candidates: () =>
        Promise.reject({ message: "HTTP 403: not_granted: credential provider `self-accounts` is not approved on this server" }),
    });
    render(<Harness profile={PROVIDER_PROFILE} />);
    await userEvent.click(screen.getByText("go"));
    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent(/approve it under Plugins.*\(not_granted\)/));
    expect(screen.queryByText("Choose an account")).not.toBeInTheDocument();
    expect(commands()).toEqual(["connect_provider_candidates"]);
  });

  it("maps a refused release to operator text", async () => {
    backend({
      connect_mfa_begin: () => Promise.resolve({ required: false, methods: [] }),
      session_open_rdp: () => Promise.reject({ message: "HTTP 404: no_match: no account of the caller matches" }),
    });
    render(<Harness profile={PROVIDER_PROFILE} />);
    await userEvent.click(screen.getByText("go"));
    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent(/pick another.*\(no_match\)/));
  });

  it("asks for no account on any other source", async () => {
    backend({ connect_mfa_begin: () => Promise.resolve({ required: false, methods: [] }) });
    const secretProfile: ConnectionProfile = {
      id: "p_s",
      name: "Shared",
      protocol: "ssh",
      credential_source: { kind: "secret", secret_id: "s" },
    };
    render(<Harness profile={secretProfile} />);
    await act(async () => {
      await userEvent.click(screen.getByText("go"));
    });
    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent("opened"));
    expect(commands()).toEqual(["connect_mfa_begin", "session_open_ssh"]);
    const req = (mockInvoke.mock.calls[1][1] as { request: Record<string, unknown> }).request;
    expect("provider_account_id" in req).toBe(false);
  });

  it("forwards the picked account to a web `form` session", async () => {
    backend({ connect_mfa_begin: () => Promise.resolve({ required: false, methods: [] }) });
    const web: ConnectionProfile = {
      ...PROVIDER_PROFILE,
      id: "p_web",
      protocol: "web",
      web: { start_url: "https://fw01.example.com/login", allowed_origins: [], login_mode: "form" },
    };
    render(<Harness profile={web} />);
    await userEvent.click(screen.getByText("go"));
    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(screen.getByTestId("result")).toHaveTextContent("opened"));
    expect(mockInvoke).toHaveBeenLastCalledWith("session_open_web", {
      request: { resource_name: "dc01", profile_id: "p_web", connect_ticket: undefined, provider_account_id: "sa_1" },
    });
  });
});
