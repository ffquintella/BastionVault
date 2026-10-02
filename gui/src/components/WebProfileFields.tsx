/**
 * Editor fields for the `web` block of a connection profile
 * (features/web-application-connect.md §1, T96 Phase 1).
 *
 * Phase 1 launches the `open` login mode only, so the editor offers only
 * that mode; a profile carrying a later mode (written by a newer client)
 * still shows it, and save-time validation explains why it can't launch.
 */

import { useState } from "react";
import { Input, Select, Textarea } from "./ui";
import { WEB_WINDOW_MAX, WEB_WINDOW_MIN, webOriginSet } from "../lib/connectionProfiles";
import type { WebClipboardMode, WebLoginMode, WebProfileSettings } from "../lib/types";

const IS_MACOS =
  typeof navigator !== "undefined" && /mac/i.test(navigator.platform || navigator.userAgent || "");

function parseOrigins(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function parseDimension(raw: string): number | undefined {
  if (!raw.trim()) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : NaN;
}

export function WebProfileFields({
  web,
  onChange,
}: {
  web: WebProfileSettings;
  onChange: (next: WebProfileSettings) => void;
}) {
  // The textarea keeps its own text so a trailing newline survives while
  // the operator is typing the next origin.
  const [originsText, setOriginsText] = useState(() => (web.allowed_origins ?? []).join("\n"));

  function patch(p: Partial<WebProfileSettings>) {
    onChange({ ...web, ...p });
  }

  const loginModeOptions: { value: WebLoginMode; label: string }[] = [
    { value: "open", label: "Open — no credential released" },
  ];
  if (web.login_mode !== "open") {
    loginModeOptions.push({ value: web.login_mode, label: `${web.login_mode} (not available yet)` });
  }

  const clipboard: WebClipboardMode = web.clipboard ?? "off";
  const effectiveOrigins = webOriginSet(web);

  return (
    <div className="grid grid-cols-2 gap-3">
      <div className="col-span-2">
        <Input
          label="Start URL"
          value={web.start_url}
          onChange={(e) => patch({ start_url: e.target.value })}
          placeholder="https://fw01.example.com/"
          hint="Where the session window opens. HTTPS only, unless insecure HTTP is allowed below. Its origin is always allowed."
        />
      </div>

      <div className="col-span-2">
        <Textarea
          label="Additional allowed origins (one per line)"
          value={originsText}
          rows={3}
          onChange={(e) => {
            setOriginsText(e.target.value);
            patch({ allowed_origins: parseOrigins(e.target.value) });
          }}
          placeholder={"https://login.microsoftonline.com\nhttps://sso.example.com"}
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          Exact <code>scheme://host[:port]</code> &mdash; no paths, no
          wildcards. Navigation to any other origin is blocked and audited.
          Add your identity provider here when the application signs in
          through single sign-on.
        </p>
        {effectiveOrigins && (
          <p className="mt-1 text-xs text-[var(--color-text-muted)] min-w-0 break-all">
            Effective allow-list: <span className="font-mono">{effectiveOrigins.join(", ")}</span>
          </p>
        )}
      </div>

      <div className="col-span-2">
        <Select
          label="Login mode"
          value={web.login_mode}
          onChange={(e) => patch({ login_mode: e.target.value as WebLoginMode })}
          options={loginModeOptions}
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          Open mode opens the application and releases nothing: you, or the
          application&rsquo;s own single sign-on, log in. Injected form,
          HTTP-auth and SSO logins arrive in later releases.
        </p>
      </div>

      <label className="col-span-2 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={web.allow_popups_same_origin_set ?? true}
          onChange={(e) =>
            patch({ allow_popups_same_origin_set: e.target.checked ? undefined : false })
          }
        />
        <span>
          <span className="font-medium">Allow pop-ups to allowed origins</span>
          <span className="block text-xs text-[var(--color-text-muted)]">
            A pop-up to an allowed origin opens in the session window itself
            (same private store, same allow-list). Pop-ups anywhere else are
            always refused.
          </span>
        </span>
      </label>

      <label className="col-span-2 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={web.allow_downloads ?? false}
          onChange={(e) => patch({ allow_downloads: e.target.checked ? true : undefined })}
        />
        <span>
          <span className="font-medium">Allow downloads</span>
          <span className="block text-xs text-[var(--color-text-muted)]">
            Off by default. When on, files save to your downloads folder and
            each download is audited by file name and size.
          </span>
        </span>
      </label>

      <label className="col-span-2 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={web.allow_insecure_http ?? false}
          onChange={(e) => patch({ allow_insecure_http: e.target.checked ? true : undefined })}
        />
        <span>
          <span className="font-medium">Allow insecure HTTP</span>
          <span className="block text-xs text-[var(--color-text-muted)]">
            Permits <code>http://</code> start URLs and origins. Anything on
            the network path can read and change the session. Leave off
            unless the appliance offers no HTTPS at all.
          </span>
        </span>
      </label>

      <div className="col-span-2">
        <Select
          label="Page clipboard access"
          value={clipboard}
          onChange={(e) => {
            const v = e.target.value as WebClipboardMode;
            patch({ clipboard: v === "off" ? undefined : v });
          }}
          options={[
            { value: "off", label: "Off (default)" },
            { value: "bidirectional", label: "Page may read and write the clipboard" },
            { value: "host-to-session", label: "Host → session only (behaves as Off today)" },
            { value: "session-to-host", label: "Session → host only (behaves as Off today)" },
          ]}
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          Controls whether the page&rsquo;s scripts can use the clipboard
          API. Your own keyboard copy and paste always works. The webview can
          only grant or refuse that access as a whole, so the one-way
          settings currently behave as Off.
          {IS_MACOS && clipboard !== "bidirectional" && (
            <>
              {" "}
              <strong className="text-[var(--color-text)]">macOS:</strong>{" "}
              WebKit can&rsquo;t gate the page clipboard, so this setting has
              no effect on this Mac.
            </>
          )}
        </p>
      </div>

      <Input
        label="Window width"
        type="number"
        value={web.window?.width?.toString() ?? ""}
        onChange={(e) =>
          patch({ window: { ...web.window, width: parseDimension(e.target.value) } })
        }
        placeholder="1280"
        hint={`${WEB_WINDOW_MIN}–${WEB_WINDOW_MAX} px`}
      />
      <Input
        label="Window height"
        type="number"
        value={web.window?.height?.toString() ?? ""}
        onChange={(e) =>
          patch({ window: { ...web.window, height: parseDimension(e.target.value) } })
        }
        placeholder="860"
        hint={`${WEB_WINDOW_MIN}–${WEB_WINDOW_MAX} px`}
      />
    </div>
  );
}
