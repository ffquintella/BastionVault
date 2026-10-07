/**
 * T38 Phase 3 — the Session Workspace window (`/workspace`).
 *
 * Pinned here: sessions are adopted from `session_list_open` (on load and
 * on every payload-less `session://placed`), the DOM-continuity rule
 * (§2: splitting or switching tabs moves the pane's host element and never
 * rebuilds its terminal), teardown (a pane closes only after the host
 * stopped its session; its host element is released exactly once; the
 * last tab closes the window), and the workspace chords.
 *
 * Phases 5–6 and the Phase 3–4 residuals add: closing a live session asks
 * first; the layout skeleton is saved (debounced) with tokens the host
 * resolves; the last run's layout is offered, refused across namespaces,
 * and restored pane by pane through the normal open path into placeholders
 * that keep the saved shape; "Pop out" and dragging a tab out move a
 * session to its own window without closing it.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const h = vi.hoisted(() => {
  type Listener = (ev: { payload: unknown }) => void;
  const listeners = new Map<string, Listener>();

  class FakeTerminal {
    static instances: FakeTerminal[] = [];
    cols = 80;
    rows = 24;
    opened: HTMLElement | null = null;
    disposed = false;
    constructor() {
      FakeTerminal.instances.push(this);
    }
    loadAddon() {}
    open(el: HTMLElement) {
      this.opened = el;
    }
    onData() {
      return { dispose: () => undefined };
    }
    onResize() {
      return { dispose: () => undefined };
    }
    onBell() {
      return { dispose: () => undefined };
    }
    attachCustomKeyEventHandler() {}
    focus() {}
    paste() {}
    write() {}
    dispose() {
      this.disposed = true;
    }
  }

  return { listeners, FakeTerminal, mockInvoke: vi.fn(), closeWindow: vi.fn() };
});

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => h.mockInvoke(...args),
  Channel: class {},
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: (ev: { payload: unknown }) => void) => {
    h.listeners.set(name, cb);
    return Promise.resolve(() => h.listeners.delete(name));
  },
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({ close: h.closeWindow }),
}));
vi.mock("@xterm/xterm", () => ({ Terminal: h.FakeTerminal }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

import { SessionWorkspaceWindow } from "../routes/SessionWorkspaceWindow";
import { useSessionWorkspaceStore } from "../stores/sessionWorkspaceStore";
import { paneHost, paneHostTokens, resetPaneHostsForTests } from "../lib/paneHosts";
import { resetSessionInputPrefsForTests } from "../lib/sessionInputPrefs";
import { activeChordBindings, type WorkspaceAction } from "../lib/reservedChords";
import { CONNECT_PALETTE_OPEN_EVENT } from "../lib/connectPaletteEvents";
import type { OpenSessionListing, SavedLayout, SessionPlacement } from "../lib/api";
import { leaves as leavesOf } from "../lib/sessionLayout";
import { LAYOUT_SAVE_DEBOUNCE_MS } from "../routes/SessionWorkspaceWindow";

function row(
  token: string,
  placement: SessionPlacement = "workspace-tab",
  attached = "session-workspace",
  extra: Partial<OpenSessionListing> = {},
): OpenSessionListing {
  return {
    token,
    protocol: "ssh",
    label: `ssh op@${token}:22`,
    resource_name: token,
    profile_id: "cp_1",
    stdout_event: `session-stdout-${token}`,
    closed_event: `session-closed-${token}`,
    resize_event: null,
    cursor_event: null,
    width: null,
    height: null,
    opened_at: `2026-10-07T08:00:0${token.length}Z`,
    placement,
    pane_ref: null,
    attached_to: attached,
    attach_epoch: 1,
    ...extra,
  };
}

let listed: OpenSessionListing[];
let closeRefusal: string | null;
let savedView: { vault_id: string; active_namespace: string; layout: SavedLayout | null };
let opened: number;

function invokedWith(cmd: string) {
  return h.mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

function chord(action: WorkspaceAction, target: EventTarget = document.body) {
  const c = activeChordBindings().byAction.get(action)!;
  const ev = new KeyboardEvent("keydown", {
    code: c.code,
    metaKey: c.meta,
    ctrlKey: c.ctrl,
    altKey: c.alt,
    shiftKey: c.shift,
    bubbles: true,
    cancelable: true,
  });
  act(() => {
    target.dispatchEvent(ev);
  });
  return ev;
}

/** Answer the "Disconnect this session?" confirmation. */
function confirmDisconnect() {
  const dialog = screen.getByRole("alertdialog", { name: "Confirm disconnect" });
  fireEvent.click(within(dialog).getByRole("button", { name: "Disconnect" }));
}

async function placed() {
  await act(async () => {
    h.listeners.get("session://placed")!({ payload: null });
  });
}

beforeEach(() => {
  h.listeners.clear();
  h.FakeTerminal.instances.length = 0;
  h.closeWindow.mockReset().mockResolvedValue(undefined);
  useSessionWorkspaceStore.getState().reset();
  resetPaneHostsForTests();
  resetSessionInputPrefsForTests();
  listed = [];
  closeRefusal = null;
  savedView = { vault_id: "v1", active_namespace: "", layout: null };
  opened = 0;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  h.mockInvoke.mockReset();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  h.mockInvoke.mockImplementation((cmd: string, args?: Record<string, any>) => {
    switch (cmd) {
      case "session_list_open":
        return Promise.resolve(listed);
      case "session_layout_get":
        return Promise.resolve(savedView);
      case "session_layout_save":
        return Promise.resolve({ saved_panes: 1 });
      case "session_move":
        listed = listed.map((r) =>
          r.token === args!.request.token
            ? { ...r, attached_to: `ssh-${r.token}`, attach_epoch: r.attach_epoch + 1 }
            : r,
        );
        return Promise.resolve({ window_label: `ssh-${args!.request.token}` });
      case "read_resource":
        if (args!.name === "gone") return Promise.resolve({ name: "gone", connection_profiles: [] });
        return Promise.resolve({
          name: args!.name,
          connection_profiles: [{ id: "cp_1", name: "ops", protocol: "ssh", credential_source: { kind: "secret" } }],
        });
      case "connect_mfa_begin":
        return Promise.resolve({ required: false });
      case "session_open_ssh": {
        opened += 1;
        const req = args!.request;
        const token = `R${opened}`;
        listed = [...listed, row(token, req.placement, "session-workspace", { pane_ref: req.restore?.pane_ref ?? null })];
        return Promise.resolve({ token, stdout_event: `session-stdout-${token}`, closed_event: "c", window_label: "session-workspace" });
      }
      case "session_close":
        if (closeRefusal) return Promise.reject({ message: closeRefusal });
        listed = listed.filter((r) => r.token !== args!.request!.token);
        return Promise.resolve(undefined);
      case "session_heartbeat":
        return Promise.resolve({ attached: listed.length });
      case "get_session_workspace_prefs":
        return Promise.resolve({
          layout_mode: "workspace",
          default_placement: "workspace-tab",
          confirm_multiline_paste: true,
          chord_overrides: {},
          replay_buffer: false,
        });
      default:
        return Promise.resolve(null);
    }
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SessionWorkspaceWindow", () => {
  it("adopts the sessions attached to it once its listener is live, as tabs, and heartbeats", async () => {
    listed = [row("A"), row("B"), row("C", "workspace-tab", "ssh-C")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    expect(h.listeners.has("session://placed")).toBe(true);
    expect(invokedWith("session_list_open")).toHaveLength(1);
    // A session rendered by its own window is not taken.
    expect(screen.queryByText("ssh op@C:22")).not.toBeInTheDocument();
    expect(screen.getAllByRole("tab")[1]).toHaveAttribute("aria-selected", "true");
    // Both panes are mounted — the background tab's too — each in its host.
    expect(h.FakeTerminal.instances).toHaveLength(2);
    expect(paneHost("A").contains(h.FakeTerminal.instances[0].opened)).toBe(true);
    expect(paneHost("A").isConnected).toBe(true);
    expect(invokedWith("session_heartbeat")).toHaveLength(1);
    expect(invokedWith("session_heartbeat")[0][1]).toBeUndefined();
  });

  it("a split moves the existing pane's host element and never rebuilds its terminal", async () => {
    listed = [row("A")];
    const { container } = render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(1));
    const termA = h.FakeTerminal.instances[0];
    const hostA = paneHost("A");
    const slotBefore = hostA.parentElement;

    listed = [...listed, row("B", "workspace-split-right")];
    await placed();
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));

    expect(paneHost("A")).toBe(hostA);
    expect(termA.disposed).toBe(false);
    expect(hostA.contains(termA.opened)).toBe(true);
    // Same node, new parent: the old slot was replaced by a split.
    expect(hostA.parentElement).not.toBe(slotBefore);
    expect(hostA.isConnected).toBe(true);
    expect(container.querySelector('[data-split="row"]')).not.toBeNull();
    expect(screen.getAllByRole("tab")).toHaveLength(1);
    expect(screen.getAllByRole("separator")).toHaveLength(1);
  });

  it("switching tabs hides the other tab instead of unmounting it", async () => {
    listed = [row("A"), row("B")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    const [termA, termB] = h.FakeTerminal.instances;
    fireEvent.click(screen.getAllByRole("tab")[0]);
    expect(screen.getAllByRole("tab")[0]).toHaveAttribute("aria-selected", "true");
    const panels = screen.getAllByRole("tabpanel", { hidden: true });
    expect(panels.map((p) => p.style.display)).toEqual(["flex", "none"]);
    expect(termA.disposed).toBe(false);
    expect(termB.disposed).toBe(false);
    expect(h.FakeTerminal.instances).toHaveLength(2);
  });

  it("closing a pane stops the session first, then releases its host exactly once", async () => {
    listed = [row("A"), row("B", "workspace-split-down")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: "Close pane ssh op@B:22" }));
    confirmDisconnect();
    await waitFor(() => expect(paneHostTokens()).toEqual(["A"]));
    expect(invokedWith("session_close").map((c) => c[1])).toEqual([{ request: { token: "B" } }]);
    expect(h.FakeTerminal.instances[1].disposed).toBe(true);
    expect(h.FakeTerminal.instances[0].disposed).toBe(false);
    // A stale list cannot bring the closed pane back.
    listed = [row("A"), row("B")];
    await placed();
    expect(screen.queryByText("ssh op@B:22")).not.toBeInTheDocument();
    expect(h.closeWindow).not.toHaveBeenCalled();
  });

  it("keeps the pane, and says why, when the host refuses to close it", async () => {
    listed = [row("A")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(1));
    closeRefusal = "session `A` is rendered by window `ssh-A`";
    fireEvent.click(screen.getByRole("button", { name: "Close pane ssh op@A:22" }));
    confirmDisconnect();
    expect(await screen.findByRole("alert")).toHaveTextContent("rendered by window `ssh-A`");
    expect(paneHostTokens()).toEqual(["A"]);
  });

  it("closing the last tab closes the window", async () => {
    listed = [row("A")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Close tab ssh op@A:22" }));
    confirmDisconnect();
    await waitFor(() => expect(h.closeWindow).toHaveBeenCalledTimes(1));
    expect(paneHostTokens()).toEqual([]);
  });

  it("runs workspace chords, and keeps them from the page and the native menu", async () => {
    listed = [row("A"), row("B", "workspace-split-right")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));
    const state = () => useSessionWorkspaceStore.getState().layout.tabs[0];

    const zoom = chord("toggleZoom");
    expect(zoom.defaultPrevented).toBe(true);
    expect(state().zoomedPaneId).toBe(state().focusedPaneId);
    chord("toggleZoom");
    expect(state().zoomedPaneId).toBeUndefined();

    chord("focusLeft");
    const left = state().focusedPaneId;
    expect(useSessionWorkspaceStore.getState().layout.tabs[0].root.kind).toBe("split");

    const opened = vi.fn();
    window.addEventListener(CONNECT_PALETTE_OPEN_EVENT, opened);
    chord("splitDown");
    expect((opened.mock.calls[0][0] as CustomEvent).detail).toEqual({ placement: "workspace-split-down" });
    window.removeEventListener(CONNECT_PALETTE_OPEN_EVENT, opened);

    chord("closePane");
    confirmDisconnect();
    await waitFor(() => expect(invokedWith("session_close")).toHaveLength(1));
    expect(invokedWith("session_close")[0][1]).toEqual({ request: { token: "A" } });
    expect(left).not.toBe(state().focusedPaneId);
  });

  it("swallows a chord typed into a text field but does not run it", async () => {
    listed = [row("A")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(1));
    const input = document.createElement("input");
    document.body.appendChild(input);
    const ev = chord("closePane", input);
    expect(ev.defaultPrevented).toBe(true);
    expect(invokedWith("session_close")).toHaveLength(0);
    input.remove();
  });

  it("an empty workspace offers to connect", async () => {
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(invokedWith("session_list_open")).toHaveLength(1));
    const opened = vi.fn();
    window.addEventListener(CONNECT_PALETTE_OPEN_EVENT, opened);
    fireEvent.click(screen.getByRole("button", { name: "Connect…" }));
    expect((opened.mock.calls[0][0] as CustomEvent).detail).toEqual({ placement: "workspace-tab" });
    window.removeEventListener(CONNECT_PALETTE_OPEN_EVENT, opened);
    expect(h.closeWindow).not.toHaveBeenCalled();
  });

  // ── Phase 3–4 residual: confirm before ending a live session ──────

  it("asks before ⌘W ends a live session, and Cancel keeps it", async () => {
    listed = [row("A")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(1));
    chord("closePane");
    const dialog = screen.getByRole("alertdialog", { name: "Confirm disconnect" });
    expect(dialog).toHaveTextContent("ssh op@A:22");
    // Chords are swallowed, not run, while it is open.
    expect(chord("closePane").defaultPrevented).toBe(true);
    expect(screen.getAllByRole("alertdialog")).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(invokedWith("session_close")).toHaveLength(0);
    expect(paneHostTokens()).toEqual(["A"]);
  });

  it("closes a pane whose session already ended without asking", async () => {
    listed = [row("A"), row("B", "workspace-split-right")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));
    act(() => useSessionWorkspaceStore.getState().setStatus("B", "closed"));
    fireEvent.click(screen.getByRole("button", { name: "Close pane ssh op@B:22" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    await waitFor(() => expect(paneHostTokens()).toEqual(["A"]));
  });

  // ── Phase 6: moving a session out ─────────────────────────────────

  it("Pop out moves the session to its own window without closing it, and a stale list cannot bring it back", async () => {
    listed = [row("A"), row("B", "workspace-split-right")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));
    const stale = [row("A"), row("B", "workspace-split-right")];
    fireEvent.click(screen.getByRole("button", { name: "Move ssh op@B:22 to its own window" }));
    await waitFor(() => expect(paneHostTokens()).toEqual(["A"]));
    expect(invokedWith("session_move").map((c) => c[1])).toEqual([{ request: { token: "B", to: "own-window" } }]);
    expect(invokedWith("session_close")).toHaveLength(0);

    // A listing from before the move: B still attached here, same epoch.
    const now = listed;
    listed = stale;
    await placed();
    expect(paneHostTokens()).toEqual(["A"]);

    // Moved back later: a new epoch, adopted again.
    listed = [...now.filter((r) => r.token !== "B"), row("B", "own-window", "session-workspace", { attach_epoch: 3 })];
    await placed();
    await waitFor(() => expect([...paneHostTokens()].sort()).toEqual(["A", "B"]));
  });

  it("dragging a tab out of the strip moves its sessions to their own windows", async () => {
    listed = [row("A"), row("B")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    const tab = screen.getAllByRole("tab")[0];
    fireEvent.pointerDown(tab, { button: 0, clientX: 20, clientY: 10, pointerId: 1 });
    act(() => {
      window.dispatchEvent(new MouseEvent("pointermove", { clientX: 25, clientY: 120 }));
      window.dispatchEvent(new MouseEvent("pointerup", { clientX: 25, clientY: 300 }));
    });
    await waitFor(() => expect(invokedWith("session_move")).toHaveLength(1));
    expect(invokedWith("session_move")[0][1]).toEqual({ request: { token: "A", to: "own-window" } });
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(1));
    expect(invokedWith("session_close")).toHaveLength(0);
  });

  // ── Phase 5: save and restore ────────────────────────────────────

  it("saves the layout skeleton, debounced, naming sessions by token only", async () => {
    listed = [row("A"), row("B", "workspace-split-right")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));
    expect(invokedWith("session_layout_save")).toHaveLength(0);
    await waitFor(() => expect(invokedWith("session_layout_save")).toHaveLength(1), {
      timeout: LAYOUT_SAVE_DEBOUNCE_MS * 3,
    });
    expect(invokedWith("session_layout_save")[0][1]).toEqual({
      layout: {
        tabs: [
          {
            root: {
              kind: "split",
              dir: "row",
              ratio: 0.5,
              a: { kind: "pane", token: "A" },
              b: { kind: "pane", token: "B" },
            },
          },
        ],
      },
    });
    // Focus is not part of a layout.
    chord("focusLeft");
    await new Promise((r) => setTimeout(r, LAYOUT_SAVE_DEBOUNCE_MS * 1.5));
    expect(invokedWith("session_layout_save")).toHaveLength(1);
  });

  const SAVED: SavedLayout = {
    saved_at: "2026-10-07T00:00:00Z",
    tabs: [
      {
        root: {
          kind: "split",
          dir: "row",
          ratio: 0.3,
          a: { kind: "pane", resource_name: "web01", profile_id: "cp_1", protocol: "ssh", namespace: "tenant-a" },
          b: { kind: "pane", resource_name: "db01", profile_id: "cp_1", protocol: "ssh", namespace: "tenant-a" },
        },
      },
    ],
  };

  it("restores the last layout through the normal open path, keeping its shape, and does not save it back", async () => {
    savedView = { vault_id: "v1", active_namespace: "tenant-a", layout: SAVED };
    render(<SessionWorkspaceWindow />);
    fireEvent.click(await screen.findByRole("button", { name: "Restore last layout (2 panes)" }));
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(2));

    const opens = invokedWith("session_open_ssh").map((c) => c[1].request);
    expect(opens).toEqual([
      {
        resource_name: "web01",
        profile_id: "cp_1",
        placement: "workspace-tab",
        restore: { namespace: "tenant-a", pane_ref: expect.stringMatching(/^r\d+$/) },
      },
      {
        resource_name: "db01",
        profile_id: "cp_1",
        placement: "workspace-tab",
        restore: { namespace: "tenant-a", pane_ref: expect.stringMatching(/^r\d+$/) },
      },
    ]);
    // Each went through the connect-time MFA gate first.
    expect(invokedWith("connect_mfa_begin")).toHaveLength(2);

    const tabs = useSessionWorkspaceStore.getState().layout.tabs;
    expect(tabs).toHaveLength(1);
    const root = tabs[0].root;
    expect(root.kind).toBe("split");
    if (root.kind === "split") expect(root.ratio).toBeCloseTo(0.3);
    expect(leavesOf(root).map((l) => l.token)).toEqual(["R1", "R2"]);
    // The restored shape is the baseline, not a change to save back.
    await new Promise((r) => setTimeout(r, LAYOUT_SAVE_DEBOUNCE_MS * 1.5));
    expect(invokedWith("session_layout_save")).toHaveLength(0);
    expect(screen.queryByRole("button", { name: /Restore last layout/ })).not.toBeInTheDocument();
  });

  it("refuses to restore a layout saved in another namespace, naming both, before opening anything", async () => {
    savedView = { vault_id: "v1", active_namespace: "tenant-b", layout: SAVED };
    render(<SessionWorkspaceWindow />);
    fireEvent.click(await screen.findByRole("button", { name: "Restore last layout (2 panes)" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("`tenant-a`");
    expect(alert).toHaveTextContent("`tenant-b`");
    expect(invokedWith("connect_mfa_begin")).toHaveLength(0);
    expect(invokedWith("session_open_ssh")).toHaveLength(0);
    expect(useSessionWorkspaceStore.getState().layout.tabs).toHaveLength(0);
  });

  it("drops a pane that cannot be restored, says why, and keeps the window open", async () => {
    savedView = {
      vault_id: "v1",
      active_namespace: "",
      layout: {
        saved_at: "",
        tabs: [{ root: { kind: "pane", resource_name: "gone", profile_id: "cp_1", protocol: "ssh", namespace: "" } }],
      },
    };
    render(<SessionWorkspaceWindow />);
    fireEvent.click(await screen.findByRole("button", { name: "Restore last layout (1 pane)" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("1 of 1 panes were not restored");
    expect(alert).toHaveTextContent("gone: profile `cp_1` no longer exists");
    expect(invokedWith("session_open_ssh")).toHaveLength(0);
    expect(useSessionWorkspaceStore.getState().layout.tabs).toHaveLength(0);
    expect(h.closeWindow).not.toHaveBeenCalled();
  });

  it("offers the last run's layout next to the tabs when a session arrived first", async () => {
    savedView = { vault_id: "v1", active_namespace: "tenant-a", layout: SAVED };
    listed = [row("A")];
    render(<SessionWorkspaceWindow />);
    await waitFor(() => expect(h.FakeTerminal.instances).toHaveLength(1));
    expect(await screen.findByRole("button", { name: "Restore last layout (2 panes)" })).toBeInTheDocument();
  });
});
