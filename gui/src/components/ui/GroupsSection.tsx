// Reusable "Groups" section rendered above the main list on pages
// that can be filtered by asset-group membership (Resources, Secrets).
// Visual style mirrors the Termius "Groups" section: dark cards in a
// responsive grid, each showing the group name + a count of items of
// the current page's kind that live in that group. Clicking a card
// toggles the page's filter to that group; clicking the active card
// clears the filter.

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

export function GroupsSection({
  groups,
  selected,
  onSelect,
  itemKindPlural,
}: GroupsSectionProps) {
  if (groups.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--color-text)]">Groups</h2>
        {selected && (
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors"
          >
            Clear filter
          </button>
        )}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {groups.map((g) => {
          const isSelected = selected === g.name;
          return (
            <button
              key={g.name}
              type="button"
              onClick={() => onSelect(isSelected ? null : g.name)}
              className={`flex items-center gap-3 p-3 rounded-xl border text-left transition-colors ${
                isSelected
                  ? "bg-[var(--color-primary)] border-[var(--color-primary)] text-white"
                  : "bg-[var(--color-surface)] border-[var(--color-border)] hover:border-[var(--color-primary)]"
              }`}
            >
              <div
                className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg font-semibold shrink-0 ${
                  isSelected
                    ? "bg-white/20 text-white"
                    : "bg-[var(--color-primary)]/10 text-[var(--color-primary)]"
                }`}
                aria-hidden="true"
              >
                {g.name.slice(0, 1).toUpperCase()}
              </div>
              <div className="min-w-0 flex-1">
                <div
                  className={`font-medium truncate ${
                    isSelected ? "text-white" : "text-[var(--color-text)]"
                  }`}
                >
                  {g.name}
                </div>
                <div
                  className={`text-xs ${
                    isSelected
                      ? "text-white/80"
                      : "text-[var(--color-text-muted)]"
                  }`}
                >
                  {g.count} {g.count === 1 ? itemKindPlural.replace(/s$/, "") : itemKindPlural}
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
