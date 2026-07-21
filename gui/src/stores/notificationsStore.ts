import { create } from "zustand";
import * as api from "../lib/api";

/**
 * In-app notification state. Backs the header bell + notification center.
 * Notifications are fetched from the caller's own inbox
 * (`v2/notifications/inbox`, server-scoped by entity id) via the Tauri
 * commands. A lightweight poll loop keeps the unread badge fresh; the
 * `notification-received` / `notification-center-open` Tauri events (from
 * plugin app modules) also nudge a refresh / open.
 */

interface NotificationsState {
  notifications: api.NotificationItem[];
  unreadCount: number;
  loading: boolean;
  error: string | null;
  /** Set when a poll surfaces a newly-arrived notification, so the
   *  Layout can raise a toast; cleared via `clearLastArrival`. */
  lastArrival: api.NotificationItem | null;
  /** Whether the notification-center dropdown is open. */
  centerOpen: boolean;

  load: () => Promise<void>;
  refreshUnread: () => Promise<void>;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  dismiss: (id: string) => Promise<void>;
  setCenterOpen: (open: boolean) => void;
  clearLastArrival: () => void;
  clear: () => void;
}

// Module-level guard so only one poll loop runs regardless of how many
// components subscribe (mirrors pluginSurfacesStore's watch guard).
let pollTimer: ReturnType<typeof setInterval> | null = null;
const POLL_MS = 30_000;

export const useNotificationsStore = create<NotificationsState>((set, get) => ({
  notifications: [],
  unreadCount: 0,
  loading: false,
  error: null,
  lastArrival: null,
  centerOpen: false,

  load: async () => {
    set({ loading: true, error: null });
    try {
      const items = await api.notificationsInbox();
      const prev = get().notifications;
      const prevIds = new Set(prev.map((n) => n.id));
      // Newest unread item we hadn't seen before → toast trigger.
      const fresh = items.find((n) => !n.read && !prevIds.has(n.id)) ?? null;
      set({
        notifications: items,
        unreadCount: items.filter((n) => !n.read).length,
        loading: false,
        lastArrival: fresh ?? get().lastArrival,
      });
    } catch (e) {
      set({ loading: false, error: String(e) });
    }

    // Start the background poll once, after the first successful load.
    if (pollTimer === null) {
      pollTimer = setInterval(() => {
        // Only poll while signed in (clear() nulls the timer on sign-out).
        void get().refreshUnread();
      }, POLL_MS);
    }
  },

  refreshUnread: async () => {
    try {
      const count = await api.notificationsUnreadCount();
      // If the badge grew, pull the full list so the center + toast see it.
      if (count > get().unreadCount) {
        await get().load();
      } else {
        set({ unreadCount: count });
      }
    } catch {
      // Transient errors are non-fatal for the badge; keep the last value.
    }
  },

  markRead: async (id) => {
    await api.notificationsMarkRead(id);
    set((s) => {
      const notifications = s.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n,
      );
      return { notifications, unreadCount: notifications.filter((n) => !n.read).length };
    });
  },

  markAllRead: async () => {
    await api.notificationsMarkAllRead();
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0,
    }));
  },

  dismiss: async (id) => {
    await api.notificationsDismiss(id);
    set((s) => {
      const notifications = s.notifications.filter((n) => n.id !== id);
      return { notifications, unreadCount: notifications.filter((n) => !n.read).length };
    });
  },

  setCenterOpen: (open) => set({ centerOpen: open }),
  clearLastArrival: () => set({ lastArrival: null }),

  clear: () => {
    if (pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    set({
      notifications: [],
      unreadCount: 0,
      loading: false,
      error: null,
      lastArrival: null,
      centerOpen: false,
    });
  },
}));
