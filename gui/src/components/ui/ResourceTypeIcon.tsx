import {
  AppWindow,
  Box,
  Camera,
  Cloud,
  Code,
  Cpu,
  Database,
  FileText,
  Globe,
  HardDrive,
  Key,
  Lock,
  Monitor,
  Network,
  Printer,
  Router,
  Server,
  Shield,
  ShieldCheck,
  Smartphone,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import type { ResourceTypeDef } from "../../lib/types";

/**
 * Curated set of Lucide icons exposed in the Settings → Resource
 * Types editor. Operators pick from this list when defining or
 * editing a custom resource type; built-in types ship with their
 * own preferred icon (`DEFAULT_RESOURCE_TYPES.<x>.icon`).
 *
 * The catalog stays small on purpose — Lucide ships hundreds of
 * icons but a focused list keeps the picker scannable. Add an
 * entry here when a real operator request shows up; don't preempt.
 */
export const RESOURCE_TYPE_ICON_CATALOG: { value: string; label: string; icon: LucideIcon }[] = [
  { value: "Server", label: "Server", icon: Server },
  { value: "Database", label: "Database", icon: Database },
  { value: "ShieldCheck", label: "Firewall (shield+check)", icon: ShieldCheck },
  { value: "Shield", label: "Shield", icon: Shield },
  { value: "Network", label: "Switch / Network", icon: Network },
  { value: "Router", label: "Router", icon: Router },
  { value: "Wifi", label: "Wireless", icon: Wifi },
  { value: "Globe", label: "Website / Internet", icon: Globe },
  { value: "AppWindow", label: "Application", icon: AppWindow },
  { value: "Code", label: "Code / Repo", icon: Code },
  { value: "Cloud", label: "Cloud", icon: Cloud },
  { value: "Cpu", label: "Compute / CPU", icon: Cpu },
  { value: "HardDrive", label: "Disk / Storage", icon: HardDrive },
  { value: "Monitor", label: "Workstation / Monitor", icon: Monitor },
  { value: "Smartphone", label: "Mobile device", icon: Smartphone },
  { value: "Camera", label: "Camera", icon: Camera },
  { value: "Printer", label: "Printer", icon: Printer },
  { value: "Key", label: "Key", icon: Key },
  { value: "Lock", label: "Lock / Vault", icon: Lock },
  { value: "FileText", label: "Document", icon: FileText },
  { value: "Box", label: "Box / Generic", icon: Box },
];

const ICONS: Record<string, LucideIcon> = Object.fromEntries(
  RESOURCE_TYPE_ICON_CATALOG.map((e) => [e.value, e.icon]),
);

const COLOR_TINTS: Record<NonNullable<ResourceTypeDef["color"]>, string> = {
  info: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  success: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30",
  warning: "text-amber-400 bg-amber-400/10 border-amber-400/30",
  error: "text-rose-400 bg-rose-400/10 border-rose-400/30",
  neutral: "text-slate-300 bg-slate-400/10 border-slate-400/30",
};

interface Props {
  typeDef: ResourceTypeDef;
  /** Icon size in pixels (default 16). */
  size?: number;
  /** When true, show the type label next to the icon. Default
   *  false — the wrapping element carries a `title` attribute so
   *  the browser renders a native tooltip on hover. */
  withLabel?: boolean;
  className?: string;
}

/**
 * Render a `ResourceTypeDef` as a Lucide icon (with native tooltip)
 * or — when no icon is configured — fall back to the legacy text
 * pill so existing custom types without an icon stay readable.
 */
export function ResourceTypeIcon({ typeDef, size = 16, withLabel = false, className = "" }: Props) {
  const Icon = typeDef.icon ? ICONS[typeDef.icon] : undefined;
  const tint = COLOR_TINTS[typeDef.color] ?? COLOR_TINTS.neutral;
  if (!Icon) {
    // Fallback: text pill matching the existing badge variants so
    // operator-defined types without an icon stay legible.
    return (
      <span
        title={typeDef.label}
        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${tint} ${className}`}
      >
        {typeDef.label}
      </span>
    );
  }
  return (
    <span
      title={typeDef.label}
      aria-label={typeDef.label}
      className={`inline-flex items-center justify-center gap-1 rounded p-1 border ${tint} ${className}`}
    >
      <Icon size={size} aria-hidden="true" />
      {withLabel && <span className="text-xs font-medium">{typeDef.label}</span>}
    </span>
  );
}
