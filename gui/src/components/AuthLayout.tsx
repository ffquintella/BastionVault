import { useState, type ReactNode } from "react";
import { TitleBar } from "./TitleBar";
import { AboutModal } from "./AboutModal";

interface AuthLayoutProps {
  children: ReactNode;
  title: string;
  subtitle?: string;
}

export function AuthLayout({ children, title, subtitle }: AuthLayoutProps) {
  // Unauth pages still need the custom title bar — `decorations: false`
  // strips OS chrome from every window, so without our own bar the
  // user has no way to drag, minimize, or close. The menu here only
  // exposes auth-agnostic items (About / Reload / Toggle Fullscreen
  // / Quit); Sign Out and Backup are hidden until the user lands in
  // the main `Layout`.
  const [aboutOpen, setAboutOpen] = useState(false);
  return (
    <div className="flex flex-col h-screen">
      <TitleBar onAbout={() => setAboutOpen(true)} />
      <div className="flex-1 flex items-center justify-center bg-[var(--color-bg)] p-4 overflow-auto">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-[var(--color-text)] mb-1">
              BastionVault
            </h1>
            <p className="text-[var(--color-text-muted)] text-sm">{subtitle}</p>
          </div>
          <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-6 shadow-xl">
            <h2 className="text-xl font-semibold mb-4">{title}</h2>
            {children}
          </div>
        </div>
      </div>
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} />
    </div>
  );
}
