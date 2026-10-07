/**
 * T38 Phase 1 — the session panes extracted from the three session
 * windows, and the one-pane route wrappers around them.
 *
 * What is pinned here is the behaviour the refactor must not change:
 * the SSH early-bytes handshake order (both listeners live before the
 * first `session_resize`), the RDP frame-channel hand-off, input
 * forwarding, the close semantics (Disconnect calls `session_close`;
 * unmount never does), and the window-level heartbeat.
 *
 * Phases 3–4 add: the SSH pane fits to its own box and reports a resize
 * only after the handshake and only when cols/rows change; the RDP pane
 * takes keys only while its canvas has focus; reserved chords are never
 * forwarded; the multi-line paste guard.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";

const h = vi.hoisted(() => {
  type Listener = (ev: { payload: unknown }) => void;
  const listeners = new Map<string, Listener>();
  const pendingListens: Array<() => void> = [];
  const state = { deferListen: false };

  class FakeTerminal {
    static instances: FakeTerminal[] = [];
    cols = 80;
    rows = 24;
    written: Array<string | Uint8Array> = [];
    pasted: string[] = [];
    focusCount = 0;
    dataCb: ((d: string) => void) | null = null;
    resizeCb: ((d: { cols: number; rows: number }) => void) | null = null;
    bellCb: (() => void) | null = null;
    keyHandler: ((e: KeyboardEvent) => boolean) | null = null;
    opened: HTMLElement | null = null;
    disposed = false;
    constructor() {
      FakeTerminal.instances.push(this);
    }
    loadAddon(addon: { term?: FakeTerminal }) {
      addon.term = this;
    }
    open(el: HTMLElement) {
      this.opened = el;
    }
    onData(cb: (d: string) => void) {
      this.dataCb = cb;
      return { dispose: () => undefined };
    }
    onResize(cb: (d: { cols: number; rows: number }) => void) {
      this.resizeCb = cb;
      return { dispose: () => undefined };
    }
    onBell(cb: () => void) {
      this.bellCb = cb;
      return { dispose: () => undefined };
    }
    attachCustomKeyEventHandler(fn: (e: KeyboardEvent) => boolean) {
      this.keyHandler = fn;
    }
    /** Like xterm: fires onResize only when the size changes. */
    resize(cols: number, rows: number) {
      if (cols === this.cols && rows === this.rows) return;
      this.cols = cols;
      this.rows = rows;
      this.resizeCb?.({ cols, rows });
    }
    focus() {
      this.focusCount++;
    }
    paste(t: string) {
      this.pasted.push(t);
    }
    write(d: string | Uint8Array) {
      this.written.push(d);
    }
    dispose() {
      this.disposed = true;
    }
  }

  /** What the next `fit()` measures; null = no change. */
  const fitTo: { size: { cols: number; rows: number } | null } = { size: null };

  class FakeResizeObserver {
    static instances: FakeResizeObserver[] = [];
    targets: Element[] = [];
    constructor(public cb: (entries: Array<{ contentRect: { width: number; height: number } }>) => void) {
      FakeResizeObserver.instances.push(this);
    }
    observe(el: Element) {
      this.targets.push(el);
    }
    disconnect() {}
    fire(width: number, height: number) {
      this.cb([{ contentRect: { width, height } }]);
    }
  }

  class FakeChannel {
    onmessage: ((m: unknown) => void) | null = null;
  }

  return {
    listeners,
    pendingListens,
    state,
    FakeTerminal,
    FakeChannel,
    FakeResizeObserver,
    fitTo,
    mockInvoke: vi.fn(),
  };
});

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => h.mockInvoke(...args),
  Channel: h.FakeChannel,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: (ev: { payload: unknown }) => void) => {
    h.listeners.set(name, cb);
    const unlisten = () => {
      h.listeners.delete(name);
    };
    if (h.state.deferListen) {
      return new Promise((resolve) => h.pendingListens.push(() => resolve(unlisten)));
    }
    return Promise.resolve(unlisten);
  },
  emit: () => Promise.resolve(),
}));

vi.mock("@xterm/xterm", () => ({ Terminal: h.FakeTerminal }));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class {
    term?: InstanceType<typeof h.FakeTerminal>;
    fit() {
      if (h.fitTo.size && this.term) this.term.resize(h.fitTo.size.cols, h.fitTo.size.rows);
    }
  },
}));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

const rustion = vi.hoisted(() => ({
  rustionRecordingRead: vi.fn(),
  fetchRecordingBytes: vi.fn(),
  rustionRecordingReplayLog: vi.fn(),
}));
vi.mock("../lib/rustion", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/rustion")>()),
  ...rustion,
}));

import { SSH_RESIZE_DEBOUNCE_MS, SshPane } from "../components/session/SshPane";
import { RdpPane } from "../components/session/RdpPane";
import { ReplayPane } from "../components/session/ReplayPane";
import { SessionSshWindow } from "../routes/SessionSshWindow";
import { SessionRdpWindow } from "../routes/SessionRdpWindow";
import { SESSION_HEARTBEAT_INTERVAL_MS } from "../lib/sessionHeartbeat";
import { resetSessionInputPrefsForTests } from "../lib/sessionInputPrefs";
import { activeChordBindings, type WorkspaceAction } from "../lib/reservedChords";

/** A keydown for whatever chord `action` is bound to on this platform. */
function chordEvent(action: WorkspaceAction, type: "keydown" | "keyup" = "keydown") {
  const c = activeChordBindings().byAction.get(action)!;
  return new KeyboardEvent(type, {
    code: c.code,
    metaKey: c.meta,
    ctrlKey: c.ctrl,
    altKey: c.alt,
    shiftKey: c.shift,
    bubbles: true,
  });
}

let prefsReply: { confirm_multiline_paste: boolean; chord_overrides: Record<string, string> };

const TOKEN = "sess_0123";
const STDOUT = `session-stdout-${TOKEN}`;
const CLOSED = `session-closed-${TOKEN}`;

function invokedWith(cmd: string) {
  return h.mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

beforeEach(() => {
  h.listeners.clear();
  h.pendingListens.length = 0;
  h.state.deferListen = false;
  h.FakeTerminal.instances.length = 0;
  h.FakeResizeObserver.instances.length = 0;
  h.fitTo.size = null;
  resetSessionInputPrefsForTests();
  prefsReply = { confirm_multiline_paste: true, chord_overrides: {} };
  vi.stubGlobal("ResizeObserver", h.FakeResizeObserver);
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
    cb(0);
    return 1;
  });
  vi.stubGlobal("cancelAnimationFrame", () => undefined);
  h.mockInvoke.mockReset();
  h.mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "session_rustion_info") return Promise.resolve(null);
    if (cmd === "session_heartbeat") return Promise.resolve({ attached: 1 });
    if (cmd === "get_session_workspace_prefs") {
      return Promise.resolve({ layout_mode: "workspace", default_placement: "workspace-tab", ...prefsReply });
    }
    return Promise.resolve(undefined);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── SSH ────────────────────────────────────────────────────────────

describe("SshPane", () => {
  function renderSsh(token = TOKEN) {
    return render(
      <SshPane token={token} stdoutEvent={STDOUT} closedEvent={CLOSED} label="ssh op@web01:22" />,
    );
  }

  it("subscribes to stdout and closed before the first session_resize (early-bytes handshake)", async () => {
    h.state.deferListen = true;
    renderSsh();
    expect(h.listeners.has(STDOUT)).toBe(true);
    expect(h.listeners.has(CLOSED)).toBe(true);
    // Neither subscription is live yet: the host must not be told to
    // drain its early-bytes buffer.
    await Promise.resolve();
    expect(invokedWith("session_resize")).toHaveLength(0);

    h.pendingListens[0]();
    await Promise.resolve();
    expect(invokedWith("session_resize")).toHaveLength(0);

    h.pendingListens[1]();
    await waitFor(() => expect(invokedWith("session_resize")).toHaveLength(1));
    expect(invokedWith("session_resize")[0][1]).toEqual({
      request: { token: TOKEN, cols: 80, rows: 24 },
    });
  });

  it("writes stdout bytes to the terminal and forwards keystrokes as base64", async () => {
    renderSsh();
    const term = h.FakeTerminal.instances[0];
    expect(term.opened).toBeInstanceOf(HTMLElement);
    act(() => h.listeners.get(STDOUT)!({ payload: { bytes_b64: btoa("hi") } }));
    expect(term.written[term.written.length - 1]).toEqual(new Uint8Array([104, 105]));

    term.dataCb!("ls\r");
    expect(invokedWith("session_input")[0][1]).toEqual({
      request: { token: TOKEN, bytes_b64: btoa("ls\r") },
    });
  });

  it("shows the close reason once, however many times the host re-emits it", async () => {
    renderSsh();
    const term = h.FakeTerminal.instances[0];
    const fire = () => h.listeners.get(CLOSED)!({ payload: { reason: "remote hung up" } });
    act(fire);
    act(fire);
    act(fire);
    expect(screen.getByText("closed")).toBeInTheDocument();
    expect(screen.getByText("remote hung up")).toBeInTheDocument();
    const banners = term.written.filter((w) => typeof w === "string" && w.includes("remote hung up"));
    expect(banners).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeDisabled();
  });

  it("Disconnect calls session_close; unmounting never does", async () => {
    const { unmount } = renderSsh();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(invokedWith("session_close")).toHaveLength(1));
    expect(invokedWith("session_close")[0][1]).toEqual({ request: { token: TOKEN } });

    unmount();
    expect(invokedWith("session_close")).toHaveLength(1);
    expect(h.FakeTerminal.instances[0].disposed).toBe(true);
    await waitFor(() => expect(h.listeners.size).toBe(0));
  });

  it("an unmount without Disconnect leaves the session to the host", () => {
    const { unmount } = renderSsh();
    unmount();
    expect(invokedWith("session_close")).toHaveLength(0);
  });

  it("refuses to start without a token", () => {
    renderSsh("");
    expect(screen.getByText("session token missing from URL")).toBeInTheDocument();
    expect(screen.getByText("error")).toBeInTheDocument();
    expect(h.FakeTerminal.instances).toHaveLength(0);
  });

  it("fits to its own box: no resize before the handshake, then only when cols/rows change", async () => {
    h.state.deferListen = true;
    renderSsh();
    const term = h.FakeTerminal.instances[0];
    const ro = h.FakeResizeObserver.instances[0];
    expect(ro.targets[0]).toBe(term.opened);

    // The slot attaches and the pane is measured before the listeners are
    // live: the terminal re-fits, but the host is not told yet.
    h.fitTo.size = { cols: 100, rows: 30 };
    act(() => ro.fire(800, 600));
    expect(term.cols).toBe(100);
    expect(invokedWith("session_resize")).toHaveLength(0);

    // The handshake carries the size as of now.
    h.pendingListens[0]();
    h.pendingListens[1]();
    await waitFor(() => expect(invokedWith("session_resize")).toHaveLength(1));
    expect(invokedWith("session_resize")[0][1]).toEqual({ request: { token: TOKEN, cols: 100, rows: 30 } });

    // Hidden (a background tab, a zoomed-out pane): skipped.
    h.fitTo.size = { cols: 2, rows: 1 };
    act(() => ro.fire(0, 0));
    expect(term.cols).toBe(100);
    // Re-shown at the same size: nothing reaches the host.
    h.fitTo.size = { cols: 100, rows: 30 };
    act(() => ro.fire(800, 600));
    expect(invokedWith("session_resize")).toHaveLength(1);
    // A divider drag: the terminal re-fits on every frame, the host hears
    // once, with the grid it settled on (T38 Phase 3 residual).
    h.fitTo.size = { cols: 70, rows: 30 };
    act(() => ro.fire(560, 600));
    h.fitTo.size = { cols: 60, rows: 30 };
    act(() => ro.fire(480, 600));
    expect(term.cols).toBe(60);
    expect(invokedWith("session_resize")).toHaveLength(1);
    await waitFor(() => expect(invokedWith("session_resize")).toHaveLength(2));
    expect(invokedWith("session_resize")[1][1]).toEqual({ request: { token: TOKEN, cols: 60, rows: 30 } });

    // Dragged away and back before it settles: nothing to tell the host.
    h.fitTo.size = { cols: 50, rows: 30 };
    act(() => ro.fire(400, 600));
    h.fitTo.size = { cols: 60, rows: 30 };
    act(() => ro.fire(480, 600));
    await new Promise((r) => setTimeout(r, SSH_RESIZE_DEBOUNCE_MS * 2));
    expect(invokedWith("session_resize")).toHaveLength(2);
  });

  /** T38 Phase 6: a handshake replay can carry a host notice (output not
   *  kept across a move, or dropped); it is written before the bytes. */
  it("writes a host notice before the bytes it came with", () => {
    renderSsh();
    const term = h.FakeTerminal.instances[0];
    act(() =>
      h.listeners.get(STDOUT)!({ payload: { bytes_b64: btoa("$ "), notice: "replaying the last 1 KiB" } }),
    );
    expect(term.written.slice(-2)).toEqual([
      "\x1b[2m[replaying the last 1 KiB]\x1b[0m\r\n",
      new Uint8Array([36, 32]),
    ]);
  });

  it("does not forward a reserved chord to the remote shell, and forwards everything else", () => {
    renderSsh();
    const handler = h.FakeTerminal.instances[0].keyHandler!;
    expect(handler(chordEvent("splitRight"))).toBe(false);
    expect(handler(chordEvent("closePane"))).toBe(false);
    expect(handler(chordEvent("releaseKeyboard"))).toBe(false);
    expect(handler(new KeyboardEvent("keydown", { code: "KeyC", ctrlKey: true }))).toBe(true);
    expect(handler(new KeyboardEvent("keydown", { code: "KeyD", ctrlKey: true }))).toBe(true);
    expect(handler(new KeyboardEvent("keydown", { code: "KeyA" }))).toBe(true);
  });

  it("reports output and the bell, and takes focus when focused", () => {
    const onActivity = vi.fn();
    const { rerender } = render(
      <SshPane
        token={TOKEN}
        stdoutEvent={STDOUT}
        closedEvent={CLOSED}
        label="ssh"
        focused={false}
        onActivity={onActivity}
      />,
    );
    const term = h.FakeTerminal.instances[0];
    expect(term.focusCount).toBe(0);
    act(() => h.listeners.get(STDOUT)!({ payload: { bytes_b64: btoa("x") } }));
    act(() => term.bellCb!());
    expect(onActivity.mock.calls).toEqual([["output"], ["bell"]]);
    rerender(
      <SshPane token={TOKEN} stdoutEvent={STDOUT} closedEvent={CLOSED} label="ssh" focused onActivity={onActivity} />,
    );
    expect(term.focusCount).toBe(1);
  });

  it("shows the host's refusal when Disconnect is refused, instead of marking the pane closed", async () => {
    h.mockInvoke.mockImplementation((cmd: string) =>
      cmd === "session_close"
        ? Promise.reject({ message: "session `x` is rendered by window `session-workspace`" })
        : Promise.resolve(null),
    );
    renderSsh();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(await screen.findByText(/rendered by window `session-workspace`/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disconnect" })).not.toBeDisabled();
  });
});

describe("SshPane paste guard", () => {
  function paste(target: HTMLElement, text: string): Event {
    const ev = new Event("paste", { bubbles: true, cancelable: true });
    Object.defineProperty(ev, "clipboardData", { value: { getData: () => text } });
    target.dispatchEvent(ev);
    return ev;
  }

  function renderSsh() {
    return render(<SshPane token={TOKEN} stdoutEvent={STDOUT} closedEvent={CLOSED} label="ssh op@db01:22" />);
  }

  it("lets a single line through untouched", async () => {
    renderSsh();
    await act(async () => {
      await Promise.resolve();
    });
    const ev = paste(h.FakeTerminal.instances[0].opened!, "uptime");
    expect(ev.defaultPrevented).toBe(false);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("holds a paste with a line break and names the target; Paste sends it, Cancel drops it", async () => {
    renderSsh();
    const term = h.FakeTerminal.instances[0];
    let ev!: Event;
    act(() => {
      ev = paste(term.opened!, "systemctl restart app\nrm -rf /tmp/x\n");
    });
    expect(ev.defaultPrevented).toBe(true);
    const dialog = screen.getByRole("alertdialog", { name: "Confirm multi-line paste" });
    expect(dialog).toHaveTextContent("Paste 2 lines");
    expect(dialog).toHaveTextContent("ssh op@db01:22");
    expect(term.pasted).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Paste" }));
    expect(term.pasted).toEqual(["systemctl restart app\nrm -rf /tmp/x\n"]);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();

    act(() => {
      paste(term.opened!, "a\nb");
    });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(term.pasted).toHaveLength(1);
  });

  it("is off only when the preference says so", async () => {
    prefsReply = { confirm_multiline_paste: false, chord_overrides: {} };
    renderSsh();
    await waitFor(() => expect(invokedWith("get_session_workspace_prefs")).toHaveLength(1));
    await act(async () => {
      await Promise.resolve();
    });
    const ev = paste(h.FakeTerminal.instances[0].opened!, "a\nb");
    expect(ev.defaultPrevented).toBe(false);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("stays on when the preferences cannot be read", async () => {
    h.mockInvoke.mockImplementation((cmd: string) =>
      cmd === "get_session_workspace_prefs" ? Promise.reject({ message: "unreadable" }) : Promise.resolve(null),
    );
    renderSsh();
    await waitFor(() => expect(invokedWith("get_session_workspace_prefs")).toHaveLength(1));
    await act(async () => {
      await Promise.resolve();
    });
    act(() => {
      paste(h.FakeTerminal.instances[0].opened!, "a\nb");
    });
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});

// ── RDP ────────────────────────────────────────────────────────────

describe("RdpPane", () => {
  const RESIZE = `session-resize-${TOKEN}`;
  const CURSOR = `session-cursor-${TOKEN}`;
  let getContext: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    getContext = vi
      .spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => ({ putImageData: vi.fn() }) as unknown as CanvasRenderingContext2D);
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
  });
  afterEach(() => {
    getContext.mockRestore();
    vi.unstubAllGlobals();
  });

  function renderRdp() {
    return render(
      <RdpPane
        token={TOKEN}
        closedEvent={CLOSED}
        resizeEvent={RESIZE}
        cursorEvent={CURSOR}
        label="rdp op@win01:3389"
        initialWidth={1280}
        initialHeight={720}
      />,
    );
  }

  it("hands the host a frame channel and opens once it is attached", async () => {
    const { container } = renderRdp();
    const canvas = container.querySelector("canvas")!;
    expect(canvas.width).toBe(1280);
    expect(canvas.height).toBe(720);
    const attach = invokedWith("session_attach_rdp_frames");
    expect(attach).toHaveLength(1);
    expect(attach[0][1]).toEqual({ request: { token: TOKEN }, channel: expect.any(h.FakeChannel) });
    await waitFor(() => expect(screen.getByText("open")).toBeInTheDocument());
    expect(h.listeners.has(CLOSED)).toBe(true);
    expect(h.listeners.has(RESIZE)).toBe(true);
    expect(h.listeners.has(CURSOR)).toBe(true);
  });

  it("names a frame channel the host refused", async () => {
    h.mockInvoke.mockImplementation((cmd: string) =>
      cmd === "session_attach_rdp_frames" ? Promise.reject("no such session") : Promise.resolve(null),
    );
    renderRdp();
    await waitFor(() =>
      expect(screen.getByText("could not attach the frame channel: no such session")).toBeInTheDocument(),
    );
  });

  it("forwards keys from its canvas while mounted and stops on unmount, without closing the session", async () => {
    const { container, unmount } = renderRdp();
    const canvas = container.querySelector("canvas")!;
    fireEvent.keyDown(canvas, { code: "KeyA" });
    fireEvent.keyUp(canvas, { code: "KeyA" });
    expect(invokedWith("session_input_rdp_key").map((c) => c[1])).toEqual([
      { request: { token: TOKEN, js_code: "KeyA", pressed: true } },
      { request: { token: TOKEN, js_code: "KeyA", pressed: false } },
    ]);
    unmount();
    fireEvent.keyDown(canvas, { code: "KeyB" });
    expect(invokedWith("session_input_rdp_key")).toHaveLength(2);
    expect(invokedWith("session_close")).toHaveLength(0);
  });

  it("captures keys per pane, not per window: a key elsewhere never reaches the desktop", () => {
    renderRdp();
    fireEvent.keyDown(window, { code: "KeyA" });
    fireEvent.keyDown(document.body, { code: "KeyB" });
    expect(invokedWith("session_input_rdp_key")).toHaveLength(0);
  });

  it("grabs the keyboard on mount and on click, and says so", async () => {
    const { container } = renderRdp();
    const canvas = container.querySelector("canvas")!;
    expect(document.activeElement).toBe(canvas);
    expect(screen.getByText(/keyboard → remote/)).toBeInTheDocument();
    act(() => canvas.blur());
    expect(screen.getByText("keyboard released")).toBeInTheDocument();
    fireEvent.mouseDown(canvas, { button: 0 });
    expect(document.activeElement).toBe(canvas);
  });

  it("does not forward a workspace chord, and the release chord gives the keyboard back", () => {
    const onRelease = vi.fn();
    const { container } = render(
      <RdpPane
        token={TOKEN}
        closedEvent={CLOSED}
        resizeEvent={RESIZE}
        cursorEvent={CURSOR}
        label="rdp"
        initialWidth={1280}
        initialHeight={720}
        onReleaseKeyboard={onRelease}
      />,
    );
    const canvas = container.querySelector("canvas")!;
    act(() => {
      canvas.dispatchEvent(chordEvent("splitRight"));
    });
    expect(invokedWith("session_input_rdp_key")).toHaveLength(0);

    // Hold Shift, then release the keyboard: Shift is released remotely
    // so it cannot stay stuck down on the desktop.
    fireEvent.keyDown(canvas, { code: "ShiftLeft", shiftKey: true });
    act(() => {
      canvas.dispatchEvent(chordEvent("releaseKeyboard"));
    });
    expect(onRelease).toHaveBeenCalledTimes(1);
    expect(document.activeElement).not.toBe(canvas);
    expect(invokedWith("session_input_rdp_key").map((c) => c[1])).toEqual([
      { request: { token: TOKEN, js_code: "ShiftLeft", pressed: true } },
      { request: { token: TOKEN, js_code: "ShiftLeft", pressed: false } },
    ]);
    // A key-up for a key whose key-down was never forwarded is dropped.
    fireEvent.keyUp(canvas, { code: "KeyD" });
    expect(invokedWith("session_input_rdp_key")).toHaveLength(2);
  });

  it("reflects the closed event", async () => {
    renderRdp();
    act(() => h.listeners.get(CLOSED)!({ payload: null }));
    expect(screen.getByText("closed")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeDisabled();
  });

  it("Disconnect calls session_close for its token", async () => {
    renderRdp();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(invokedWith("session_close")).toHaveLength(1));
    expect(invokedWith("session_close")[0][1]).toEqual({ request: { token: TOKEN } });
  });
});

// ── Replay ─────────────────────────────────────────────────────────

describe("ReplayPane", () => {
  const ENTRY = {
    recordingId: "rec_1",
    sessionId: "s",
    authority: "rustion-a",
    format: "smb-log",
    sha256: "",
    sizeBytes: 4,
    startedAt: "",
    finishedAt: "",
    targetHost: "files01",
    targetUser: "op",
    correlationId: "",
    bastionId: "",
    receivedAt: "",
    deliveryMode: "webhook",
  };

  beforeEach(() => {
    rustion.rustionRecordingRead.mockReset().mockResolvedValue(ENTRY);
    rustion.fetchRecordingBytes.mockReset().mockResolvedValue({
      recordingId: "rec_1",
      format: "smb-log",
      sha256: "",
      bytes: new TextEncoder().encode("open a\nread a\n"),
    });
    rustion.rustionRecordingReplayLog.mockReset().mockResolvedValue(undefined);
  });

  it("loads, logs the replay and renders the format's view; Close is the host's", async () => {
    const onClose = vi.fn();
    const { container } = render(<ReplayPane recordingId="rec_1" onClose={onClose} />);
    await waitFor(() => expect(screen.getByText("2 operations recorded")).toBeInTheDocument());
    expect(screen.getByText("rec_1")).toBeInTheDocument();
    expect(rustion.rustionRecordingReplayLog).toHaveBeenCalledWith("rec_1", false);
    expect(container.firstElementChild).not.toHaveClass("min-h-screen");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("fills the viewport only when asked", async () => {
    const { container } = render(<ReplayPane recordingId="rec_1" onClose={() => undefined} fillViewport />);
    await waitFor(() => expect(screen.getByText("2 operations recorded")).toBeInTheDocument());
    expect(container.firstElementChild).toHaveClass("min-h-screen");
  });

  it("names a recording that failed to load", async () => {
    rustion.rustionRecordingRead.mockRejectedValue(new Error("permission denied"));
    render(<ReplayPane recordingId="rec_1" onClose={() => undefined} />);
    await waitFor(() => expect(screen.getByText("Failed to load recording")).toBeInTheDocument());
    expect(screen.getByText("permission denied")).toBeInTheDocument();
  });
});

// ── One-pane windows ───────────────────────────────────────────────

describe("session window wrappers", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("the SSH window passes its URL params to the pane and heartbeats once per interval", async () => {
    vi.useFakeTimers();
    const url =
      `/session/ssh?token=${TOKEN}&stdout=${encodeURIComponent(STDOUT)}` +
      `&closed=${encodeURIComponent(CLOSED)}&label=${encodeURIComponent("ssh op@web01:22")}`;
    const { unmount } = render(
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/session/ssh" element={<SessionSshWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("ssh op@web01:22")).toBeInTheDocument();
    expect(h.listeners.has(STDOUT)).toBe(true);
    expect(h.listeners.has(CLOSED)).toBe(true);
    // One beat on mount. It names no window: the host derives the
    // window from the call itself.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(invokedWith("session_heartbeat")).toEqual([["session_heartbeat", undefined]]);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(SESSION_HEARTBEAT_INTERVAL_MS);
    });
    expect(invokedWith("session_heartbeat")).toHaveLength(2);

    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SESSION_HEARTBEAT_INTERVAL_MS * 3);
    });
    expect(invokedWith("session_heartbeat")).toHaveLength(2);
  });

  it("the RDP window passes geometry through and heartbeats", async () => {
    const getContext = vi
      .spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => ({ putImageData: vi.fn() }) as unknown as CanvasRenderingContext2D);
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        disconnect() {}
      },
    );
    const url = `/session/rdp?token=${TOKEN}&closed=${CLOSED}&resize=r&cursor=c&label=rdp&w=1600&h=900`;
    const { container } = render(
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/session/rdp" element={<SessionRdpWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    const canvas = container.querySelector("canvas")!;
    expect(canvas.width).toBe(1600);
    expect(canvas.height).toBe(900);
    await waitFor(() => expect(invokedWith("session_heartbeat")).toHaveLength(1));
    getContext.mockRestore();
    vi.unstubAllGlobals();
  });

  it("a window without a token sends no heartbeat", async () => {
    render(
      <MemoryRouter initialEntries={["/session/ssh"]}>
        <Routes>
          <Route path="/session/ssh" element={<SessionSshWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    await act(async () => {
      await Promise.resolve();
    });
    expect(invokedWith("session_heartbeat")).toHaveLength(0);
  });

  /** T38 Phase 6: a session's own window can hand its session to the
   *  workspace — in workspace mode only; the session keeps running. */
  it("offers Move to workspace in workspace mode and asks the host to move the session", async () => {
    render(
      <MemoryRouter initialEntries={[`/session/ssh?token=${TOKEN}&stdout=${STDOUT}&closed=${CLOSED}&label=ssh`]}>
        <Routes>
          <Route path="/session/ssh" element={<SessionSshWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Move to workspace" }));
    await waitFor(() => expect(invokedWith("session_move")).toHaveLength(1));
    expect(invokedWith("session_move")[0][1]).toEqual({ request: { token: TOKEN, to: "workspace" } });
    expect(invokedWith("session_close")).toHaveLength(0);
  });

  it("does not offer Move to workspace in the Separate windows layout", async () => {
    h.mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_session_workspace_prefs") {
        return Promise.resolve({ layout_mode: "windows", default_placement: "own-window", ...prefsReply });
      }
      return Promise.resolve(undefined);
    });
    render(
      <MemoryRouter initialEntries={[`/session/ssh?token=${TOKEN}&stdout=${STDOUT}&closed=${CLOSED}&label=ssh`]}>
        <Routes>
          <Route path="/session/ssh" element={<SessionSshWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(invokedWith("get_session_workspace_prefs")).toHaveLength(1));
    await act(async () => {
      await Promise.resolve();
    });
    expect(screen.queryByRole("button", { name: "Move to workspace" })).not.toBeInTheDocument();
  });
});
