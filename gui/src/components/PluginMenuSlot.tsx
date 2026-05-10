import { Link, useLocation } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";
import { usePluginSurfacesStore } from "../stores/pluginSurfacesStore";
import type { SurfaceSection } from "../lib/api";

/**
 * Sidebar slot that renders every plugin-contributed menu entry
 * whose `section` matches the prop. Filters out entries the active
 * token's policies wouldn't satisfy (`min_policy` is a UX hint —
 * server ACLs remain authoritative). Renders nothing when no
 * matching menus exist, so the slot can sit unconditionally
 * inside Layout without inserting empty `<div>`s.
 */
export function PluginMenuSlot({ section }: { section: SurfaceSection }) {
  const location = useLocation();
  const policies = useAuthStore((s) => s.policies);
  const menusForSection = usePluginSurfacesStore((s) => s.menusForSection);
  const items = menusForSection(section, policies);
  if (items.length === 0) return null;
  return (
    <div className="mt-1 space-y-0.5">
      {items.map(({ menu }) => {
        const active = location.pathname.startsWith(menu.route);
        return (
          <Link
            key={menu.id}
            to={menu.route}
            className={`block px-2 py-1.5 rounded-md text-sm transition-colors truncate ${
              active
                ? "bg-[var(--color-primary-soft)] text-[var(--color-primary)]"
                : "text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
            }`}
            title={menu.label}
          >
            {menu.label}
          </Link>
        );
      })}
    </div>
  );
}
