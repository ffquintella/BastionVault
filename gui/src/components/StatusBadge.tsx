interface StatusBadgeProps {
  status: "ok" | "warning" | "error";
  label: string;
}

export function StatusBadge({ status, label }: StatusBadgeProps) {
  const colors = {
    ok: "bg-green-500/20 text-green-400 border-green-500/30",
    warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    error: "bg-red-500/20 text-red-400 border-red-500/30",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${colors[status]}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          status === "ok"
            ? "bg-green-400"
            : status === "warning"
              ? "bg-yellow-400"
              : "bg-red-400"
        }`}
      />
      {label}
    </span>
  );
}
