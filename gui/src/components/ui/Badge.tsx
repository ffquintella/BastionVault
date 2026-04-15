type Variant = "success" | "warning" | "error" | "info" | "neutral";

const variantStyles: Record<Variant, string> = {
  success: "bg-green-500/20 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  error: "bg-red-500/20 text-red-400 border-red-500/30",
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  neutral: "bg-[var(--color-surface-hover)] text-[var(--color-text-muted)] border-[var(--color-border)]",
};

const dotColors: Record<Variant, string> = {
  success: "bg-green-400",
  warning: "bg-yellow-400",
  error: "bg-red-400",
  info: "bg-blue-400",
  neutral: "bg-[var(--color-text-muted)]",
};

interface BadgeProps {
  variant?: Variant;
  label: string;
  dot?: boolean;
}

export function Badge({ variant = "neutral", label, dot = false }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${variantStyles[variant]}`}
    >
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotColors[variant]}`} />}
      {label}
    </span>
  );
}
