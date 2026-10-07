/**
 * T38 — Settings → General → Session layout (Phases 0 and 3) and Session
 * keyboard & paste (Phase 4).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ToastProvider } from "../components/ui/Toast";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import { SessionLayoutCard } from "../components/SessionLayoutCard";
import { SessionKeyboardCard } from "../components/SessionKeyboardCard";
import { useSessionPrefsStore } from "../stores/sessionPrefsStore";
import { RESERVED_CHORDS, detectPlatform } from "../lib/reservedChords";

type Stored = {
  layout_mode: string;
  default_placement: string;
  confirm_multiline_paste: boolean;
  chord_overrides: Record<string, string>;
  replay_buffer?: boolean;
};

let stored: Stored;

function renderCards(which: "layout" | "keyboard" | "both" = "layout") {
  return render(
    <ToastProvider>
      {which !== "keyboard" && <SessionLayoutCard />}
      {which !== "layout" && <SessionKeyboardCard />}
    </ToastProvider>,
  );
}

function setCalls() {
  return mockInvoke.mock.calls.filter((c) => c[0] === "set_session_workspace_prefs").map((c) => c[1].prefs);
}

beforeEach(() => {
  useSessionPrefsStore.getState().reset();
  stored = {
    layout_mode: "workspace",
    default_placement: "workspace-tab",
    confirm_multiline_paste: true,
    chord_overrides: {},
  };
  mockInvoke.mockReset();
  mockInvoke.mockImplementation((cmd: string, args?: { prefs?: Stored }) => {
    if (cmd === "get_session_workspace_prefs") return Promise.resolve({ ...stored });
    if (cmd === "set_session_workspace_prefs") {
      stored = { ...args!.prefs! };
      return Promise.resolve(undefined);
    }
    if (cmd === "session_workspace_open") return Promise.resolve(undefined);
    if (cmd === "session_layout_forget") return Promise.resolve(true);
    return Promise.reject(new Error(`unexpected ${cmd}`));
  });
});

describe("SessionLayoutCard", () => {
  it("shows the stored mode, the isolation trade-off and the default placement", async () => {
    renderCards();
    const workspace = await screen.findByRole("radio", { name: /Session workspace/ });
    expect(workspace).toBeChecked();
    expect(screen.getByRole("radio", { name: /Separate windows/ })).not.toBeChecked();
    expect(screen.getByText(/share that window's webview/)).toBeInTheDocument();
    expect(screen.getByText(/native window tabs/)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /A new session opens in/ })).toHaveValue("workspace-tab");
  });

  it("saves only the layout mode, keeping every other key", async () => {
    renderCards();
    fireEvent.click(await screen.findByRole("radio", { name: /Separate windows/ }));
    await waitFor(() => expect(setCalls()).toEqual([{ ...stored, layout_mode: "windows" }]));
    expect(setCalls()[0]).toEqual({
      layout_mode: "windows",
      default_placement: "workspace-tab",
      confirm_multiline_paste: true,
      chord_overrides: {},
      // A host older than Phase 6 sent none: written back as off.
      replay_buffer: false,
    });
    await waitFor(() => expect(screen.getByRole("radio", { name: /Separate windows/ })).toBeChecked());
    expect(await screen.findByText(/Session layout saved/)).toBeInTheDocument();
    // The placement choice applies to workspace mode only.
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  });

  /** T38 Phase 6: the output replay ring is opt-in and says what it holds. */
  it("offers the replay buffer off by default and saves it when ticked", async () => {
    renderCards();
    const box = await screen.findByRole("checkbox", { name: /Keep recent terminal output/ });
    expect(box).not.toBeChecked();
    expect(screen.getByText(/secrets too; it is never written to disk/)).toBeInTheDocument();
    fireEvent.click(box);
    await waitFor(() => expect(setCalls()[0].replay_buffer).toBe(true));
  });

  /** T38 Phase 5: the workspace can be opened on its own (its empty state
   *  offers the restore), and the saved layout forgotten. */
  it("opens the workspace and forgets the saved layout", async () => {
    renderCards();
    fireEvent.click(await screen.findByRole("button", { name: "Open the Session Workspace" }));
    await waitFor(() => expect(mockInvoke.mock.calls.some((c) => c[0] === "session_workspace_open")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Forget the saved layout" }));
    expect(await screen.findByText("Saved session layout forgotten.")).toBeInTheDocument();
    expect(screen.getByText(/never a\s+credential or session output/)).toBeInTheDocument();
  });

  it("saves the default placement", async () => {
    renderCards();
    fireEvent.change(await screen.findByRole("combobox", { name: /A new session opens in/ }), {
      target: { value: "own-window" },
    });
    await waitFor(() => expect(setCalls()[0].default_placement).toBe("own-window"));
  });

  it("keeps the previous choice and shows the host's refusal", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_session_workspace_prefs") return Promise.resolve({ ...stored });
      return Promise.reject({ message: "preferences: could not write" });
    });
    renderCards();
    fireEvent.click(await screen.findByRole("radio", { name: /Separate windows/ }));
    expect(await screen.findByText("preferences: could not write")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Session workspace/ })).toBeChecked();
  });

  it("reports preferences it could not read", async () => {
    mockInvoke.mockRejectedValue({ message: "Failed to parse preferences: eof" });
    renderCards();
    expect(await screen.findByText("Failed to parse preferences: eof")).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });
});

describe("SessionKeyboardCard", () => {
  const platform = detectPlatform();
  const ok = platform === "mac" ? "Meta+Shift+KeyR" : "Ctrl+Shift+KeyR";

  function overrideInput(label: string) {
    return screen.getByRole("textbox", { name: `Override for ${label}` });
  }

  it("lists every reserved chord with its default, and the paste guard on", async () => {
    renderCards("keyboard");
    expect(await screen.findByRole("checkbox", { name: /Ask before pasting/ })).toBeChecked();
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(RESERVED_CHORDS.length);
    expect(within(rows[0]).getByText(RESERVED_CHORDS[0].label)).toBeInTheDocument();
  });

  it("refuses a chord the remote shell needs, and a conflict, before saving", async () => {
    renderCards("keyboard");
    await screen.findByRole("checkbox", { name: /Ask before pasting/ });
    fireEvent.change(overrideInput("Split right (opens the Connect palette)"), { target: { value: "Ctrl+C" } });
    expect(screen.getByText(/the remote shell needs it/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save chords" })).toBeDisabled();

    const newTab = platform === "mac" ? "Meta+T" : "Ctrl+Shift+T";
    fireEvent.change(overrideInput("Split right (opens the Connect palette)"), { target: { value: newTab } });
    expect(screen.getByText(/conflicts with “New tab/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save chords" })).toBeDisabled();
    expect(setCalls()).toEqual([]);
  });

  it("saves a valid override in canonical form; the layout card then keeps it", async () => {
    renderCards("both");
    await screen.findByRole("checkbox", { name: /Ask before pasting/ });
    fireEvent.change(overrideInput("Split right (opens the Connect palette)"), {
      target: { value: ok.replace("Key", "").toLowerCase() },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save chords" }));
    await waitFor(() => expect(setCalls()).toHaveLength(1));
    expect(setCalls()[0].chord_overrides).toEqual({ splitRight: ok });

    fireEvent.click(screen.getByRole("radio", { name: /Separate windows/ }));
    await waitFor(() => expect(setCalls()).toHaveLength(2));
    expect(setCalls()[1]).toMatchObject({ layout_mode: "windows", chord_overrides: { splitRight: ok } });
  });

  it("turns the paste guard off only when asked", async () => {
    renderCards("keyboard");
    fireEvent.click(await screen.findByRole("checkbox", { name: /Ask before pasting/ }));
    await waitFor(() => expect(setCalls()[0].confirm_multiline_paste).toBe(false));
    expect(await screen.findByText(/runs as it arrives/)).toBeInTheDocument();
  });

  it("names a stored override that is not applied", async () => {
    stored.chord_overrides = { splitRight: "Ctrl+KeyC" };
    renderCards("keyboard");
    expect(await screen.findByText(/Not applied: splitRight = Ctrl\+KeyC/)).toBeInTheDocument();
  });
});
