// Reusable "Groups" section rendered above the main list on pages
// that can be filtered by asset-group membership (Resources, Secrets).
// Visual style mirrors the Termius "Groups" section: dark cards in a
// responsive grid, each showing the group name + a count of items of
// the current page's kind that live in that group. Clicking a card
// toggles the page's filter to that group; clicking the active card
// clears the filter.

import { useMemo, useState } from "react";

interface GroupCard {
  name: string;
  count: number;
}

interface GroupsSectionProps {
  /** Groups that have at least one member of this page's kind. */
  groups: GroupCard[];
  /** Currently-active filter group name, or `null` for "no filter". */
  selected: string | null;
  /** Called when the user clicks a card (pass the clicked name) or
   *  the active card (pass `null` to clear). */
  onSelect: (name: string | null) => void;
  /** Label for the item kind in a single card ("resources", "secrets"). */
  itemKindPlural: string;
}

// Show the search box once the list is long enough to need it.
const SEARCH_THRESHOLD = 8;

export function GroupsSection({
  groups,
  selected,
  onSelect,
  itemKindPlural,
}: GroupsSectionProps) {
  const [query, setQuery] = useState("");
  const showSearch = groups.length > SEARCH_THRESHOLD;

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!showSearch || !q) return groups;
    // Keep the active group visible even if it doesn't match the query.
    return groups.filter((g) => g.name.toLowerCase().includes(q) || g.name === selected);
  }, [groups, query, showSearch, selected]);

  if (groups.length === 0) return null;

  const singular = itemKindPlural.replace(/s$/, "");

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-[var(--color-text)] shrink-0">
          Groups <span className="font-normal text-[var(--color-text-muted)]">({groups.length})</span>
        </h2>
        {showSearch && (
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search groups"
            aria-label="Search groups"
            className="min-w-0 flex-1 sm:flex-none sm:w-64 px-2.5 py-1 text-xs rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary)]"
          />
        )}
        {selected && (
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors shrink-0"
          >
            Clear filter
          </button>
        )}
      </div>
      {/* Capped at a quarter of the viewport height; scrolls beyond that. */}
      <div className="max-h-[25vh] overflow-y-auto pr-1">
        {visible.length === 0 ? (
          <div className="text-xs text-[var(--color-text-muted)] py-2">
            No groups match "{query}".
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-2">
            {visible.map((g) => {
              const isSelected = selected === g.name;
              return (
                <button
                  key={g.name}
                  type="button"
                  title={`${g.name} (${g.count} ${g.count === 1 ? singular : itemKindPlural})`}
                  onClick={() => onSelect(isSelected ? null : g.name)}
                  className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-left transition-colors min-w-0 ${
                    isSelected
                      ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                      : "bg-[var(--color-surface)] border-[var(--color-border)] hover:border-[var(--color-primary)]"
                  }`}
                >
                  <div
                    className={`w-6 h-6 rounded-md flex items-center justify-center text-xs font-semibold shrink-0 ${
                      isSelected
                        ? "bg-white/20 text-white"
                        : "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                    }`}
                    aria-hidden="true"
                  >
                    {g.name.slice(0, 1).toUpperCase()}
                  </div>
                  <span
                    className={`min-w-0 flex-1 truncate text-sm font-medium ${
                      isSelected ? "text-white" : "text-[var(--color-text)]"
                    }`}
                  >
                    {g.name}
                  </span>
                  <span
                    className={`text-xs shrink-0 ${
                      isSelected ? "text-white/80" : "text-[var(--color-text-muted)]"
                    }`}
                  >
                    {g.count}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
