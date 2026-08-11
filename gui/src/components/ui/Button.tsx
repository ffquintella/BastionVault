import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";
type Size = "sm" | "md" | "lg";

// Every hover style is gated on `enabled:` — Tailwind's bare `hover:` still
// fires on a disabled button, so a disabled `primary` used to brighten to
// `--color-primary-hover` under the cursor and read as clickable.
//
// The `disabled:` half replaces the variant's own colour with a neutral
// surface: opacity alone left a blue `primary` or red `danger` looking live,
// since a 50%-opacity accent is still an accent. `ghost` keeps its
// transparent background (a filled grey chip would read louder disabled than
// enabled) and leans on the shared muted text instead.
const variantStyles: Record<Variant, string> = {
  primary:
    "bg-[var(--color-primary)] text-white border-transparent " +
    "enabled:hover:bg-[var(--color-primary-hover)] " +
    "disabled:bg-[var(--color-surface-hover)] disabled:border-[var(--color-border)]",
  secondary:
    "bg-[var(--color-surface-hover)] text-[var(--color-text)] border-[var(--color-border)] " +
    "enabled:hover:bg-[var(--color-border)] " +
    "disabled:bg-[var(--color-surface-hover)] disabled:border-[var(--color-border)]",
  danger:
    "bg-red-500/20 text-red-400 border-red-500/30 " +
    "enabled:hover:bg-red-500/30 " +
    "disabled:bg-[var(--color-surface-hover)] disabled:border-[var(--color-border)]",
  ghost:
    "bg-transparent text-[var(--color-text-muted)] border-transparent " +
    "enabled:hover:bg-[var(--color-surface-hover)] enabled:hover:text-[var(--color-text)] " +
    "disabled:bg-transparent disabled:border-transparent",
};

// Shared across variants: reduced contrast, no cursor affordance, and
// `saturate-50` so a child that paints its own colour (a badge, an icon that
// doesn't use `currentColor`) fades along with the button.
const disabledStyles =
  "disabled:opacity-60 disabled:saturate-50 disabled:cursor-not-allowed " +
  "disabled:text-[var(--color-text-muted)] disabled:shadow-none";

const sizeStyles: Record<Size, string> = {
  sm: "px-2.5 py-1 text-xs gap-1",
  md: "px-3.5 py-2 text-sm gap-1.5",
  lg: "px-5 py-2.5 text-base gap-2",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: ReactNode;
  loading?: boolean;
  fullWidth?: boolean;
}

export function Button({
  variant = "primary",
  size = "md",
  icon,
  loading,
  fullWidth,
  children,
  disabled,
  className = "",
  ...props
}: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center font-medium rounded-lg border transition-colors
        focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]/40
        ${disabledStyles}
        ${variantStyles[variant]} ${sizeStyles[size]}
        ${fullWidth ? "w-full" : ""}
        ${className}`}
      {...props}
    >
      {loading ? (
        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
      ) : icon ? (
        <span className="shrink-0">{icon}</span>
      ) : null}
      {children}
    </button>
  );
}
