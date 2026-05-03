import type { ReactNode } from "react";

interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => ReactNode;
  className?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (item: T) => string;
  emptyMessage?: string;
  onRowClick?: (item: T) => void;
  /** Extra classes applied to the underlying `<table>`. Use `"table-fixed"`
   *  together with explicit `col.className` widths when cell content (long
   *  hex serials, full DNs) needs to truncate inside narrow containers. */
  tableClassName?: string;
}

export function Table<T>({
  columns,
  data,
  rowKey,
  emptyMessage = "No data",
  onRowClick,
  tableClassName = "",
}: TableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="text-center py-8 text-sm text-[var(--color-text-muted)]">
        {emptyMessage}
      </div>
    );
  }

  return (
    <table className={`w-full text-sm ${tableClassName}`.trim()}>
      <thead>
        <tr className="text-[var(--color-text-muted)] text-left">
          {columns.map((col) => (
            <th key={col.key} className={`pb-2 font-medium ${col.className || ""}`}>
              {col.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((item) => (
          <tr
            key={rowKey(item)}
            className={`border-t border-[var(--color-border)] ${
              onRowClick
                ? "hover:bg-[var(--color-surface-hover)] cursor-pointer transition-colors"
                : ""
            }`}
            onClick={() => onRowClick?.(item)}
          >
            {columns.map((col) => (
              <td key={col.key} className={`py-2.5 ${col.className || ""}`}>
                {col.render
                  ? col.render(item)
                  : String((item as Record<string, unknown>)[col.key] ?? "")}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
