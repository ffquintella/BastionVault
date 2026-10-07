/**
 * T108 — a session's own window asks before its native close (close
 * button, Alt+F4, ⌘W) ends a live session (`lib/sessionWindowClose`,
 * features/session-workspace.md §8).
 *
 * Pinned here: the window takes over `tauri://close-requested` only when it
 * has a session; with the session live it asks, naming it, and answers the
 * host (`session_window_closing`) only once the question is on screen —
 * the host force-closes a window that does not answer, so a page that
 * cannot show the question must not answer; Cancel keeps the window and the
 * session; Disconnect and close asks the host to close the calling window
 * (`session_window_close`, no window named) and never stops the session
 * itself; a session that has ended closes without asking; and a refused
 * close is reported. The workspace's half is in `sessionWorkspace.test.tsx`.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";

const h = vi.hoisted(() => {
  const listeners = new Map<string, (ev: { payload: unknown }) => void>();
  const windowListeners = new Map<string, () => void>();

  class FakeTerminal {
    cols = 80;
    rows = 24;
    loadAddon() {}
    open() {}
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
    dispose() {}
  }

  return { listeners, windowListeners, FakeTerminal, mockInvoke: vi.fn(), pluginClose: vi.fn() };
});

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => h.mockInvoke(...args),
  Channel: class {
    onmessage: ((m: unknown) => void) | null = null;
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: (ev: { payload: unknown }) => void) => {
    h.listeners.set(name, cb);
    return Promise.resolve(() => h.listeners.delete(name));
  },
  emit: () => Promise.resolve(),
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    close: h.pluginClose,
    destroy: h.pluginClose,
    listen: (name: string, cb: () => void) => {
      h.windowListeners.set(name, cb);
      return Promise.resolve(() => h.windowListeners.delete(name));
    },
  }),
}));
vi.mock("@xterm/xterm", () => ({ Terminal: h.FakeTerminal }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

import { SessionSshWindow } from "../routes/SessionSshWindow";
import { SessionRdpWindow } from "../routes/SessionRdpWindow";
import { resetSessionInputPrefsForTests } from "../lib/sessionInputPrefs";
import { WINDOW_CLOSE_REQUESTED_EVENT, isLiveStatus } from "../lib/sessionWindowClose";

const TOKEN = "sess_0123";
const CLOSED = `session-closed-${TOKEN}`;
const SSH_URL = `/session/ssh?token=${TOKEN}&stdout=session-stdout-${TOKEN}&closed=${CLOSED}&label=${encodeURIComponent(
  "ssh op@web01:22",
)}`;

let closeRefusal: string | null;
/** Whether the question was on screen each time the host was answered. */
let askingWhenAnswered: boolean[];

function invokedWith(cmd: string) {
  return h.mockInvoke.mock.calls.filter((c) => c[0] === cmd);
}

function renderSsh(url = SSH_URL) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/session/ssh" element={<SessionSshWindow />} />
      </Routes>
    </MemoryRouter>,
  );
}

async function nativeClose() {
  await act(async () => {
    h.windowListeners.get(WINDOW_CLOSE_REQUESTED_EVENT)!();
  });
}

beforeEach(() => {
  h.listeners.clear();
  h.windowListeners.clear();
  h.pluginClose.mockReset();
  resetSessionInputPrefsForTests();
  closeRefusal = null;
  askingWhenAnswered = [];
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
    },
  );
  h.mockInvoke.mockReset();
  h.mockInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case "session_heartbeat":
        return Promise.resolve({ attached: 1 });
      case "session_rustion_info":
        return Promise.resolve(null);
      case "get_session_workspace_prefs":
        return Promise.resolve({
          layout_mode: "windows",
          default_placement: "own-window",
          confirm_multiline_paste: true,
          chord_overrides: {},
        });
      case "session_window_closing":
        askingWhenAnswered.push(document.querySelector('[aria-label="Confirm close window"]') !== null);
        return Promise.resolve(undefined);
      case "session_window_close":
        return closeRefusal ? Promise.reject({ message: closeRefusal }) : Promise.resolve(undefined);
      default:
        return Promise.resolve(undefined);
    }
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("isLiveStatus", () => {
  it("counts an open, connecting or not-yet-reported session as live", () => {
    expect([undefined, "connecting", "open"].map((s) => isLiveStatus(s as never))).toEqual([true, true, true]);
    expect(isLiveStatus("closed")).toBe(false);
    expect(isLiveStatus("error")).toBe(false);
  });
});

describe("a session's own window — native close (T108)", () => {
  it("asks before closing a live session, answering the host only once the question is shown; Cancel keeps it", async () => {
    renderSsh();
    await waitFor(() => expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(true));

    await nativeClose();
    const dialog = screen.getByRole("alertdialog", { name: "Confirm close window" });
    expect(dialog).toHaveTextContent("Close this window?");
    expect(dialog).toHaveTextContent("ssh op@web01:22");
    await waitFor(() => expect(askingWhenAnswered).toEqual([true]));
    // The request names no window: the host answers for the caller.
    expect(invokedWith("session_window_closing")[0][1]).toBeUndefined();

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(invokedWith("session_window_close")).toHaveLength(0);
    expect(invokedWith("session_close")).toHaveLength(0);
    expect(h.pluginClose).not.toHaveBeenCalled();

    // Asked again later: a new question, answered again.
    await nativeClose();
    await waitFor(() => expect(askingWhenAnswered).toEqual([true, true]));
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("Disconnect and close asks the host to close this window and does not stop the session itself", async () => {
    renderSsh();
    await waitFor(() => expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(true));
    await nativeClose();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect and close" }));
    await waitFor(() => expect(invokedWith("session_window_close")).toHaveLength(1));
    expect(invokedWith("session_window_close")[0][1]).toBeUndefined();
    // The host stops the session when the window is destroyed — one path.
    expect(invokedWith("session_close")).toHaveLength(0);
    // Never Tauri's window plugin: the window is not granted it.
    expect(h.pluginClose).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("closes at once, without asking or answering, once the session has ended", async () => {
    renderSsh();
    await waitFor(() => expect(h.listeners.has(CLOSED)).toBe(true));
    await act(async () => {
      h.listeners.get(CLOSED)!({ payload: { reason: "remote closed" } });
    });
    await nativeClose();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    await waitFor(() => expect(invokedWith("session_window_close")).toHaveLength(1));
    expect(invokedWith("session_window_closing")).toHaveLength(0);
  });

  it("says why when the host does not close the window, and keeps the session", async () => {
    closeRefusal = "close window `ssh-sess_0123`: window not found";
    renderSsh();
    await waitFor(() => expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(true));
    await nativeClose();
    fireEvent.click(screen.getByRole("button", { name: "Disconnect and close" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The window was not closed");
    expect(alert).toHaveTextContent("window not found");
    fireEvent.click(within(alert).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(invokedWith("session_close")).toHaveLength(0);
  });

  it("leaves the close alone in a window with no session, and stops listening when it unmounts", async () => {
    const empty = renderSsh("/session/ssh");
    await act(async () => {
      await Promise.resolve();
    });
    expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(false);
    empty.unmount();

    const { unmount } = renderSsh();
    await waitFor(() => expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(true));
    unmount();
    expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(false);
  });

  it("an RDP window asks too", async () => {
    const getContext = vi
      .spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => ({ putImageData: vi.fn() }) as unknown as CanvasRenderingContext2D);
    render(
      <MemoryRouter initialEntries={[`/session/rdp?token=${TOKEN}&closed=${CLOSED}&resize=r&cursor=c&label=rdp%20win01`]}>
        <Routes>
          <Route path="/session/rdp" element={<SessionRdpWindow />} />
        </Routes>
      </MemoryRouter>,
    );
    await waitFor(() => expect(h.windowListeners.has(WINDOW_CLOSE_REQUESTED_EVENT)).toBe(true));
    await nativeClose();
    expect(screen.getByRole("alertdialog", { name: "Confirm close window" })).toHaveTextContent("rdp win01");
    await waitFor(() => expect(askingWhenAnswered).toEqual([true]));
    getContext.mockRestore();
  });
});
