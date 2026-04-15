interface BreadcrumbProps {
  segments: { label: string; onClick?: () => void }[];
}

export function Breadcrumb({ segments }: BreadcrumbProps) {
  return (
    <nav className="flex items-center gap-1 text-sm">
      {segments.map((seg, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <span className="text-[var(--color-text-muted)]">/</span>}
          {seg.onClick ? (
            <button
              onClick={seg.onClick}
              className="text-[var(--color-primary)] hover:underline"
            >
              {seg.label}
            </button>
          ) : (
            <span className="text-[var(--color-text)]">{seg.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}
