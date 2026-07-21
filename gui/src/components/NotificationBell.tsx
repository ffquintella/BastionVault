import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useNotificationsStore } from "../stores/notificationsStore";
import type { NotificationItem, NotificationSeverity } from "../lib/api";

/** Dot colour per severity, using theme CSS variables where possible. */
function severityColor(sev: NotificationSeverity): string {
  switch (sev) {
    case "critical":
      return "var(--color-danger, #dc2626)";
    case "warning":
      return "var(--color-warning, #d97706)";
    case "success":
      return "var(--color-success, #16a34a)";
    default:
      return "var(--color-accent, #2563eb)";
  }
}

function relativeTime(iso?: string): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/**
 * Header notification bell with an unread badge and a dropdown
 * notification center. Reads everything from `useNotificationsStore`;
 * the store owns the poll loop + event-driven refreshes.
 */
export function NotificationBell() {
  const navigate = useNavigate();
  const unread = useNotificationsStore((s) => s.unreadCount);
  const notifications = useNotificationsStore((s) => s.notifications);
  const open = useNotificationsStore((s) => s.centerOpen);
  const setOpen = useNotificationsStore((s) => s.setCenterOpen);
  const load = useNotificationsStore((s) => s.load);
  const markRead = useNotificationsStore((s) => s.markRead);
  const markAllRead = useNotificationsStore((s) => s.markAllRead);
  const dismiss = useNotificationsStore((s) => s.dismiss);

  const containerRef = useRef<HTMLDivElement | null>(null);

  // Load the inbox once on mount (starts the poll loop) and whenever the
  // center is opened, so it reflects the latest state.
  useEffect(() => {
    void load();
  }, [load]);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open, setOpen]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) void load();
  };

  const onItemClick = (n: NotificationItem) => {
    if (!n.read) void markRead(n.id);
    if (n.action_url) {
      setOpen(false);
      if (n.action_url.startsWith("/")) navigate(n.action_url);
      else window.open(n.action_url, "_blank");
    }
  };

  const badge = unread > 99 ? "99+" : String(unread);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        aria-label={`Notifications${unread ? ` (${unread} unread)` : ""}`}
        onClick={toggle}
        className="relative flex items-center justify-center w-8 h-8 rounded hover:bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        {unread > 0 && (
          <span
            className="absolute -top-0.5 -right-0.5 min-w-4 h-4 px-1 rounded-full text-[10px] leading-4 font-semibold text-white text-center"
            style={{ backgroundColor: "var(--color-danger, #dc2626)" }}
          >
            {badge}
          </span>
        )}
      </button>

      {open && (
        <div
          className="absolute left-0 top-9 z-50 w-80 max-h-[70vh] flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg"
          role="dialog"
          aria-label="Notification center"
        >
          <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--color-border)]">
            <span className="text-sm font-semibold">Notifications</span>
            <button
              type="button"
              className="text-xs text-[var(--color-accent,#2563eb)] hover:underline disabled:opacity-40"
              disabled={unread === 0}
              onClick={() => void markAllRead()}
            >
              Mark all read
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="px-3 py-8 text-center text-xs text-[var(--color-text-muted)]">
                No notifications.
              </div>
            ) : (
              notifications.map((n) => (
                <div
                  key={n.id}
                  className={`group flex gap-2 px-3 py-2 border-b border-[var(--color-border)] last:border-0 ${
                    n.read ? "" : "bg-[var(--color-surface-hover)]"
                  }`}
                >
                  <span
                    className="mt-1.5 w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: severityColor(n.severity) }}
                    aria-hidden="true"
                  />
                  <button
                    type="button"
                    className="flex-1 min-w-0 text-left"
                    onClick={() => onItemClick(n)}
                  >
                    <div className="flex items-center gap-1">
                      <span className={`text-sm truncate ${n.read ? "font-normal" : "font-semibold"}`}>
                        {n.title}
                      </span>
                    </div>
                    {n.body && (
                      <p className="text-xs text-[var(--color-text-muted)] line-clamp-2">{n.body}</p>
                    )}
                    <span className="text-[10px] text-[var(--color-text-muted)]">
                      {relativeTime(n.delivered_at || n.created_at)}
                    </span>
                  </button>
                  <button
                    type="button"
                    aria-label="Dismiss"
                    className="opacity-0 group-hover:opacity-100 text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                    onClick={() => void dismiss(n.id)}
                  >
                    <svg className="w-3.5 h-3.5" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                      <path d="M3 3l6 6M9 3l-6 6" strokeLinecap="round" />
                    </svg>
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
