import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "../components/ui/Toast";
import { useNotificationsStore } from "../stores/notificationsStore";

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

const SAMPLE = [
  {
    id: "n1",
    title: "Scheduled maintenance",
    body: "Tonight at 22:00 UTC",
    severity: "warning",
    source: "user:admin",
    created_at: "2026-07-21T10:00:00Z",
    delivered_at: "2026-07-21T10:00:00Z",
    read: false,
  },
  {
    id: "n2",
    title: "Backup complete",
    body: "",
    severity: "success",
    source: "system",
    created_at: "2026-07-20T10:00:00Z",
    delivered_at: "2026-07-20T10:00:00Z",
    read: true,
  },
];

describe("NotificationBell", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    useNotificationsStore.getState().clear();
    mockInvoke.mockImplementation((cmd: string) => {
      switch (cmd) {
        case "notifications_inbox":
          return Promise.resolve(SAMPLE);
        case "notifications_unread_count":
          return Promise.resolve(1);
        case "notifications_mark_all_read":
          return Promise.resolve(2);
        default:
          return Promise.reject(new Error(`unmocked: ${cmd}`));
      }
    });
  });

  it("shows the unread badge from the inbox", async () => {
    const { NotificationBell } = await import("../components/NotificationBell");
    renderWithProviders(<NotificationBell />);
    // One unread item → badge "1".
    await waitFor(() => expect(screen.getByText("1")).toBeInTheDocument());
  });

  it("opens the center and lists notifications on click", async () => {
    const { NotificationBell } = await import("../components/NotificationBell");
    renderWithProviders(<NotificationBell />);
    await waitFor(() => expect(screen.getByText("1")).toBeInTheDocument());

    await userEvent.click(screen.getByLabelText(/Notifications/));
    expect(screen.getByText("Scheduled maintenance")).toBeInTheDocument();
    expect(screen.getByText("Backup complete")).toBeInTheDocument();
  });

  it("mark-all-read clears the badge", async () => {
    const { NotificationBell } = await import("../components/NotificationBell");
    renderWithProviders(<NotificationBell />);
    await waitFor(() => expect(screen.getByText("1")).toBeInTheDocument());

    await userEvent.click(screen.getByLabelText(/Notifications/));
    await userEvent.click(screen.getByText("Mark all read"));

    await waitFor(() =>
      expect(useNotificationsStore.getState().unreadCount).toBe(0),
    );
  });
});
