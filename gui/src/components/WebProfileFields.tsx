/**
 * Editor fields for the `web` block of a connection profile
 * (features/web-application-connect.md §1, T96 Phases 1-3).
 *
 * `open`, `form` and `http-auth` launch. `form` adds the exposure notice, the
 * credential source (rendered by the parent through `credentialSlot`, which
 * owns the resource's secrets) and the recipe editor; `http-auth` the notice
 * and the credential source, with no recipe. A profile carrying a later mode
 * (written by a newer client) still shows it, and save-time validation
 * explains why it can't launch.
 */

import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { Input, Select, Textarea } from "./ui";
import { WebRecipeEditor } from "./WebRecipeEditor";
import * as api from "../lib/api";
import { WEB_WINDOW_MAX, WEB_WINDOW_MIN, webOriginSet } from "../lib/connectionProfiles";
import { isHeuristicRecipe } from "../lib/webRecipe";
import {
  evaluateWebExposure,
  requiredExposureForLoginMode,
  savedTypeEntry,
  type ExposureVerdict,
} from "../lib/webExposure";
import type { WebClipboardMode, WebLoginMode, WebProfileSettings } from "../lib/types";

const IS_MACOS =
  typeof navigator !== "undefined" && /mac/i.test(navigator.platform || navigator.userAgent || "");

/**
 * What the server's policy will say about a `form` or `http-auth` launch of
 * this resource.
 * Read from the *saved* `config/types` (the server never sees the builtins
 * the GUI merges in), so a type the GUI shows as opted in can still be
 * refused. `unknown` means the saved configuration could not be read; then
 * the editor says it can't tell rather than guessing either way.
 */
export type WebExposureState =
  | { kind: "loading" }
  | { kind: "unknown"; reason: string }
  | { kind: "checked"; verdict: ExposureVerdict };

export function useWebExposureState(
  resource: Record<string, unknown>,
  web: Pick<WebProfileSettings, "login_mode" | "recipe" | "allow_insecure_http">,
): WebExposureState {
  const active = web.login_mode === "form" || web.login_mode === "http-auth";
  const [saved, setSaved] = useState<
    { kind: "loading" } | { kind: "error"; reason: string } | { kind: "ok"; config: Record<string, unknown> | null }
  >({ kind: "loading" });

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    api
      .resourceTypesRead()
      .then((config) => {
        if (!cancelled) setSaved({ kind: "ok", config });
      })
      .catch((e: unknown) => {
        if (!cancelled) setSaved({ kind: "error", reason: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [active]);

  if (saved.kind === "loading") return { kind: "loading" };
  if (saved.kind === "error") return { kind: "unknown", reason: saved.reason };
  return {
    kind: "checked",
    verdict: evaluateWebExposure({
      typeDef: savedTypeEntry(saved.config, String(resource["type"] ?? "")),
      resource,
      // `form` needs `dom`, `http-auth` `handler` (spec §6).
      required: requiredExposureForLoginMode(web.login_mode) ?? "dom",
      heuristic: web.login_mode === "form" && isHeuristicRecipe(web.recipe),
      allowInsecureHttp: web.allow_insecure_http === true,
    }),
  };
}

/** Inline notice for the exposure policy: the server refuses form and
 *  http-auth mode unless the resource's saved type opts in. */
export function WebExposureNotice({
  state,
  mode = "form",
}: {
  state: WebExposureState;
  mode?: "form" | "http-auth";
}) {
  const what = mode === "http-auth" ? "HTTP-authentication logins" : "form logins";
  // The cap that admits this mode (insecure HTTP always needs `dom`).
  const needed = mode === "http-auth" ? "handler" : "dom";
  if (state.kind === "loading") return null;
  if (state.kind === "unknown") {
    return (
      <p className="text-xs text-[var(--color-text-muted)]" data-testid="exposure-unknown">
        Could not read the resource type configuration, so this editor can&rsquo;t tell whether the server
        will allow {what} for this resource ({state.reason}). The server decides at connect time.
      </p>
    );
  }
  const refusal = state.verdict.refusal;
  if (refusal === null) {
    return (
      <p className="text-xs text-[var(--color-text-muted)]" data-testid="exposure-ok">
        This resource&rsquo;s type allows {what} (exposure cap <code>{state.verdict.cap}</code>).{" "}
        {mode === "http-auth"
          ? "The credential goes to the webview's own authentication handler, never into the page."
          : "The password is in the page\u2019s DOM between fill and submit."}
      </p>
    );
  }
  return (
    <div
      role="alert"
      data-testid="exposure-refused"
      className="rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2 text-xs min-w-0"
    >
      <p className="font-medium">
        The server will refuse this profile&rsquo;s {mode === "http-auth" ? "HTTP-authentication" : "form"} login.
      </p>
      <p className="mt-1 min-w-0 break-words">
        <code>{refusal.code}</code>: {refusal.message}.
      </p>
      <p className="mt-1">
        {refusal.fixAt === "type" && (
          <>
            An administrator opts a type in under{" "}
            <Link className="underline" to="/settings">
              Settings &rarr; Resource Types
            </Link>{" "}
            (edit the type, set &ldquo;Web exposure cap&rdquo; to <code>{needed}</code>
            {mode === "http-auth" && " or higher"}
            {refusal.code === "heuristic_not_allowed" && ", and allow heuristic fill"}).
          </>
        )}
        {refusal.fixAt === "resource" && (
          <>The resource itself sets this limit; edit the resource&rsquo;s <code>web_exposure_max</code> /{" "}
          <code>allow_heuristic_fill</code>, or ask an administrator.</>
        )}
        {refusal.fixAt === "profile" && (
          <>Turn off &ldquo;Allow insecure HTTP&rdquo; below, or raise the type&rsquo;s cap to <code>dom</code>{" "}
          under{" "}
          <Link className="underline" to="/settings">
            Settings &rarr; Resource Types
          </Link>
          .</>
        )}
      </p>
    </div>
  );
}

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
  resource,
  onLoginModeChange,
  credentialSlot,
  onRecipeTextError,
}: {
  web: WebProfileSettings;
  onChange: (next: WebProfileSettings) => void;
  /** The resource record: its `type` and the resource-tier exposure keys
   *  feed the exposure notice. */
  resource?: Record<string, unknown>;
  /** Switches the mode on the whole profile, because the modes disagree on
   *  the credential source. Falls back to patching the `web` block alone. */
  onLoginModeChange?: (mode: WebLoginMode) => void;
  /** The credential-source editor, shown for `form`. */
  credentialSlot?: ReactNode;
  /** See {@link WebRecipeEditor}. */
  onRecipeTextError?: (message: string | null) => void;
}) {
  const exposure = useWebExposureState(resource ?? {}, web);
  // The textarea keeps its own text so a trailing newline survives while
  // the operator is typing the next origin.
  const [originsText, setOriginsText] = useState(() => (web.allowed_origins ?? []).join("\n"));

  function patch(p: Partial<WebProfileSettings>) {
    onChange({ ...web, ...p });
  }

  const loginModeOptions: { value: WebLoginMode; label: string }[] = [
    { value: "open", label: "Open — no credential released" },
    { value: "form", label: "Form — fill a login recipe with the credential" },
    { value: "http-auth", label: "HTTP authentication — answer Basic / Digest / NTLM sign-in natively" },
  ];
  if (web.login_mode !== "open" && web.login_mode !== "form" && web.login_mode !== "http-auth") {
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
          onChange={(e) => {
            const mode = e.target.value as WebLoginMode;
            if (onLoginModeChange) onLoginModeChange(mode);
            else patch({ login_mode: mode });
          }}
          options={loginModeOptions}
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          Open mode opens the application and releases nothing: you, or the
          application&rsquo;s own single sign-on, log in. Form mode signs in
          for you by filling the application&rsquo;s login form from a
          recipe. HTTP authentication answers the browser-level sign-in
          prompt (Basic, Digest or NTLM) many appliances use, without
          touching the page. SSO logins arrive in a later release.
        </p>
      </div>

      {web.login_mode === "http-auth" && (
        <>
          <div className="col-span-2 space-y-2 min-w-0">
            <WebExposureNotice state={exposure} mode="http-auth" />
            <p className="text-xs text-[var(--color-text-muted)]">
              <strong className="text-[var(--color-text)]">Exposure, plainly:</strong> the desktop app answers the
              application&rsquo;s HTTP sign-in challenge itself, natively &mdash; the page never receives the
              password and no recipe is involved. It answers only challenges from this profile&rsquo;s origins,
              over HTTPS, once per realm; a second challenge means the password was rejected, and is reported as
              a failed sign-in. Kerberos / Negotiate and client certificates are refused. Basic authentication
              sends the password to the server on every request (inside TLS), so the application itself sees it.
            </p>
          </div>
          {credentialSlot && <div className="col-span-2 space-y-2 min-w-0">{credentialSlot}</div>}
        </>
      )}

      {web.login_mode === "form" && (
        <>
          <div className="col-span-2 space-y-2 min-w-0">
            <WebExposureNotice state={exposure} />
            <p className="text-xs text-[var(--color-text-muted)]">
              <strong className="text-[var(--color-text)]">Exposure, plainly:</strong> with a form login the
              password exists in the application&rsquo;s own page from fill until submit, where the page&rsquo;s
              scripts (and any script injected into it) could read it. The operator never sees it, and the
              fill happens only on the profile&rsquo;s origins, in the top page, into visible fields.
            </p>
          </div>
          {credentialSlot && <div className="col-span-2 space-y-2 min-w-0">{credentialSlot}</div>}
          <div className="col-span-2 min-w-0">
            <h4 className="mb-2 text-sm font-medium">Login recipe</h4>
            <WebRecipeEditor
              recipe={web.recipe}
              onChange={(recipe) => {
                const next = { ...web };
                if (recipe === undefined) delete next.recipe;
                else next.recipe = recipe;
                onChange(next);
              }}
              web={web}
              onTextError={onRecipeTextError}
            />
          </div>
        </>
      )}

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
            unless the appliance offers no HTTPS at all. A form or HTTP
            authentication login over plain HTTP needs the type&rsquo;s cap at{" "}
            <code>dom</code>.
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
