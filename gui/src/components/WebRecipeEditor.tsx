/**
 * Editor for the login recipe of a `form`-mode web profile
 * (features/web-application-connect.md §2, T96 Phase 2).
 *
 * A structured step / action list with a raw JSON view, vendor presets,
 * JSON import / export (file and clipboard), and a "Test recipe" dry run.
 * Everything the operator can type is held to `validateWebRecipe` — a port of
 * the server's strict parser — and the recipe's URLs to the profile's origin
 * set, so the editor refuses what the server would refuse, naming the field.
 * A recipe is data: nothing here evaluates imported text.
 */

import { useEffect, useRef, useState } from "react";
import { Badge, Button, Input, Select, Textarea } from "./ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import type {
  WebLoginRecipe,
  WebProfileSettings,
  WebRecipeAction,
  WebRecipeStep,
} from "../lib/types";
import {
  MAX_ACTIONS_PER_STEP,
  MAX_STEPS,
  MAX_TIMEOUT_SECS,
  WEB_RECIPE_VENDORS,
  blankRecipe,
  checkRecipeOrigins,
  formatRecipeIssue,
  heuristicRecipe,
  isHeuristicRecipe,
  parseRecipeJson,
  recipeFileName,
  recipeToJson,
  validateWebRecipe,
} from "../lib/webRecipe";
import { recipeBaseOrigin, strictOriginSet } from "../lib/webFormProfile";
import { WEB_RECIPE_PRESETS, findPreset, presetLabel } from "../lib/webRecipePresets";

type Verb = "fill" | "click" | "submit" | "wait";
type FillKind = "username" | "password" | "totp" | "literal";

function verbOf(a: WebRecipeAction): Verb {
  if ("fill" in a) return "fill";
  if ("click" in a) return "click";
  if ("submit" in a) return "submit";
  return "wait";
}

function selectorOf(a: WebRecipeAction): string {
  if ("fill" in a) return a.fill;
  if ("click" in a) return a.click;
  if ("submit" in a) return a.submit;
  return a.wait;
}

function fillKindOf(value: string): FillKind {
  return value.startsWith("literal:") ? "literal" : (value as FillKind);
}

function withVerb(a: WebRecipeAction, verb: Verb): WebRecipeAction {
  const sel = selectorOf(a);
  if (verb === "fill") return { fill: sel, value: "username" };
  if (verb === "click") return { click: sel };
  if (verb === "submit") return { submit: sel };
  return { wait: sel };
}

function withSelector(a: WebRecipeAction, sel: string): WebRecipeAction {
  if ("fill" in a) return { ...a, fill: sel };
  if ("click" in a) return { click: sel };
  if ("submit" in a) return { submit: sel };
  return { wait: sel };
}

/** True when the structured view can draw this value without crashing; a
 *  value that fails this is shown in the JSON view only. */
function drawable(r: unknown): r is WebLoginRecipe {
  if (typeof r !== "object" || r === null) return false;
  const rec = r as Partial<WebLoginRecipe>;
  if (typeof rec.success_when !== "object" || rec.success_when === null) return false;
  if (rec.failure_when !== undefined && (typeof rec.failure_when !== "object" || rec.failure_when === null)) {
    return false;
  }
  if (rec.steps === "auto") return true;
  if (!Array.isArray(rec.steps)) return false;
  return rec.steps.every(
    (s) =>
      typeof s === "object" &&
      s !== null &&
      typeof s.when_url === "string" &&
      Array.isArray(s.actions) &&
      s.actions.every(
        (a) =>
          typeof a === "object" &&
          a !== null &&
          Object.keys(a).length >= 1 &&
          typeof selectorOf(a) === "string" &&
          (!("fill" in a) || typeof a.value === "string"),
      ),
  );
}

function move<T>(list: T[], from: number, to: number): T[] {
  if (to < 0 || to >= list.length) return list;
  const out = [...list];
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

/** Friendly wording for the fill routine's per-action verdicts. Unknown
 *  verdicts are shown as they come. */
const STATUS_HELP: Record<string, string> = {
  ok: "Found exactly one usable field",
  not_reached: "The page for this step was not loaded during the test",
  no_match: "No element matches the selector",
  ambiguous: "More than one element matches; make the selector unique",
  bad_selector: "The selector is not valid CSS",
  wrong_type: "The field is not the expected input type",
  not_input: "The match is not an <input> element",
  not_visible: "The field is hidden or too small",
  occluded: "Something covers the field",
  disabled: "The field is disabled",
  form_action: "The form posts to an origin outside the allow-list",
  form_target: "The form submits into a named frame, which the allow-list cannot police",
  no_form: "The match is not inside a form",
  unsupported: "The page does not support this check",
  not_top: "Not the top-level page",
  origin: "The page is on an origin outside the allow-list",
  script_error: "The check script failed on this page",
};

function statusVariant(status: string): "success" | "warning" | "error" | "neutral" {
  if (status === "ok") return "success";
  if (status === "not_reached") return "neutral";
  if (status === "no_match" || status === "ambiguous" || status === "bad_selector") return "error";
  return "warning";
}

export function WebRecipeTestReport({ result }: { result: api.WebRecipeTestResponse }) {
  const { report } = result;
  return (
    <div className="space-y-2 text-xs" data-testid="recipe-test-report">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant={report.outcome === "complete" ? "success" : "warning"}
          label={`Outcome: ${report.outcome}`}
        />
        <span className="min-w-0 truncate font-mono text-[var(--color-text-muted)]" title={result.recipe_hash}>
          {result.recipe_hash}
        </span>
      </div>
      {report.heuristic && report.heuristic_check && (
        <div className="rounded border border-[var(--color-border)] p-2">
          <p className="font-medium">Heuristic scan: {report.heuristic_check.verdict}</p>
          <p className="text-[var(--color-text-muted)]">
            username {report.heuristic_check.scan.username} &middot; current-password{" "}
            {report.heuristic_check.scan.current_password} &middot; password{" "}
            {report.heuristic_check.scan.password} &middot; one-time-code{" "}
            {report.heuristic_check.scan.otp}. Would fill:{" "}
            {report.heuristic_check.would_fill.length > 0
              ? report.heuristic_check.would_fill.join(", ")
              : "nothing"}
            .
          </p>
        </div>
      )}
      {report.steps.map((s) => (
        <div key={s.index} className="rounded border border-[var(--color-border)] p-2">
          <p className="font-medium">
            Step {s.index + 1}{" "}
            <span className="font-normal text-[var(--color-text-muted)]">
              {s.reached ? `reached on ${s.origin ?? "an allowed origin"}` : "not reached"}
            </span>
          </p>
          <ul className="mt-1 space-y-1">
            {s.actions.map((a) => (
              <li key={a.index} className="flex flex-wrap items-center gap-2">
                <span className="w-24 shrink-0 font-mono">
                  {a.index + 1}. {a.kind}
                  {a.value ? ` ${a.value}` : ""}
                </span>
                <Badge variant={statusVariant(a.status)} label={a.status} />
                <span className="text-[var(--color-text-muted)]">
                  {a.matches === null ? "" : `${a.matches} match${a.matches === 1 ? "" : "es"}`}
                  {STATUS_HELP[a.status] ? ` — ${STATUS_HELP[a.status]}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <p className="text-[var(--color-text-muted)]">
        Success condition {report.success_seen ? "seen" : "not seen"} &middot; failure condition{" "}
        {report.failure_seen ? "seen" : "not seen"}
        {report.origins_seen.length > 0 && (
          <>
            {" "}
            &middot; origins visited: <span className="font-mono break-all">{report.origins_seen.join(", ")}</span>
          </>
        )}
      </p>
    </div>
  );
}

export function WebRecipeEditor({
  recipe,
  onChange,
  web,
  onTextError,
}: {
  recipe: WebLoginRecipe | undefined;
  onChange: (next: WebLoginRecipe | undefined) => void;
  web: WebProfileSettings;
  /** Reports JSON text in the raw view that is not parseable JSON, so the
   *  parent can hold Save: the profile keeps the last good recipe meanwhile. */
  onTextError?: (message: string | null) => void;
}) {
  const [view, setView] = useState<"structured" | "json">("structured");
  const [jsonText, setJsonText] = useState(() => (recipe ? recipeToJson(recipe) : ""));
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [presetId, setPresetId] = useState("");
  const [appliedPreset, setAppliedPreset] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<api.WebRecipeTestResponse | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  // The recipe value this editor last handed to `onChange`, so an edit made
  // in the raw view isn't overwritten by the echo of its own change.
  const selfChange = useRef<unknown>(recipe);

  const baseOrigin = recipeBaseOrigin(web);
  const set = strictOriginSet(web);
  const allowHttp = web.allow_insecure_http === true;

  const parsed = recipe === undefined ? null : validateWebRecipe(recipe);
  const originIssue =
    parsed && parsed.ok && !("error" in set) ? checkRecipeOrigins(parsed.recipe, set.origins, allowHttp) : null;
  const problem = parsed === null ? null : !parsed.ok ? formatRecipeIssue(parsed.issue) : originIssue ? formatRecipeIssue(originIssue) : null;

  // Keep the raw view in step with edits made elsewhere (structured view,
  // preset, import), but never overwrite text the operator is typing.
  useEffect(() => {
    if (recipe !== selfChange.current) {
      selfChange.current = recipe;
      setJsonText(recipe ? recipeToJson(recipe) : "");
      setJsonError(null);
      onTextError?.(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recipe]);

  // A pending text error must not outlive the editor (switching the login
  // mode to open unmounts it), or Save would stay held for nothing.
  const onTextErrorRef = useRef(onTextError);
  onTextErrorRef.current = onTextError;
  useEffect(() => () => onTextErrorRef.current?.(null), []);

  function emit(next: WebLoginRecipe | undefined) {
    selfChange.current = next;
    setJsonText(next ? recipeToJson(next) : "");
    setJsonError(null);
    onTextError?.(null);
    setTestResult(null);
    setTestError(null);
    onChange(next);
  }

  function replaceWith(next: WebLoginRecipe, preset: string | null) {
    setAppliedPreset(preset);
    setNotice(null);
    emit(next);
  }

  // ── Starting points ──────────────────────────────────────────────────
  function applyStart() {
    if (!baseOrigin || !presetId) return;
    if (presetId === "__blank") return replaceWith(blankRecipe(baseOrigin), null);
    if (presetId === "__auto") return replaceWith(heuristicRecipe(baseOrigin), null);
    const preset = findPreset(presetId);
    if (preset) replaceWith(preset.build(baseOrigin), preset.id);
  }

  // ── Raw view ─────────────────────────────────────────────────────────
  function onJsonEdit(text: string) {
    setJsonText(text);
    setAppliedPreset(null);
    setTestResult(null);
    if (text.trim() === "") {
      setJsonError(null);
      onTextError?.(null);
      selfChange.current = undefined;
      onChange(undefined);
      return;
    }
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch (e) {
      const msg = `The text is not valid JSON (${e instanceof Error ? e.message : "parse error"}). The profile keeps the last valid recipe until it is fixed.`;
      setJsonError(msg);
      onTextError?.(msg);
      return;
    }
    setJsonError(null);
    onTextError?.(null);
    // Pushed as-is when it parses: the strict check below (and Save) then
    // name the offending field, rather than the text vanishing.
    selfChange.current = value;
    onChange(value as WebLoginRecipe);
  }

  // ── Import / export ──────────────────────────────────────────────────
  function importText(text: string, source: string) {
    const r = parseRecipeJson(text);
    if (!r.ok) {
      setNotice({ kind: "error", text: `Import from ${source} refused — ${formatRecipeIssue(r.issue)}` });
      return;
    }
    replaceWith(r.recipe, null);
    setNotice({ kind: "ok", text: `Imported a recipe from ${source}. Check its URLs against this profile, then test it.` });
  }

  async function onFile(file: File | undefined) {
    if (!file) return;
    try {
      importText(await file.text(), `file ${file.name}`);
    } catch (e: unknown) {
      setNotice({ kind: "error", text: `Could not read the file: ${extractError(e)}` });
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  async function pasteFromClipboard() {
    try {
      importText(await navigator.clipboard.readText(), "the clipboard");
    } catch (e: unknown) {
      setNotice({ kind: "error", text: `Could not read the clipboard: ${extractError(e)}. Paste into the JSON view instead.` });
    }
  }

  async function copyJson() {
    if (!recipe) return;
    try {
      await navigator.clipboard.writeText(recipeToJson(recipe));
      setNotice({ kind: "ok", text: "Recipe JSON copied to the clipboard." });
    } catch (e: unknown) {
      setNotice({ kind: "error", text: `Could not write the clipboard: ${extractError(e)}` });
    }
  }

  function downloadJson() {
    if (!recipe) return;
    try {
      const url = URL.createObjectURL(new Blob([recipeToJson(recipe)], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = recipeFileName(recipe);
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setNotice({ kind: "error", text: `Could not start the download: ${extractError(e)}. Use Copy JSON instead.` });
    }
  }

  // ── Dry run ──────────────────────────────────────────────────────────
  const canTest =
    recipe !== undefined && parsed !== null && parsed.ok && originIssue === null && !("error" in set) && !testing;

  async function runTest() {
    if (!canTest || !recipe) return;
    setTesting(true);
    setTestError(null);
    setTestResult(null);
    try {
      setTestResult(
        await api.webRecipeTest({
          url: web.start_url.trim(),
          recipe,
          allowed_origins: web.allowed_origins ?? [],
          allow_insecure_http: allowHttp,
          tls_pin_sha256: web.tls_pin_sha256 ?? [],
        }),
      );
    } catch (e: unknown) {
      setTestError(extractError(e));
    } finally {
      setTesting(false);
    }
  }

  // ── Structured edits ─────────────────────────────────────────────────
  const explicit = recipe !== undefined && drawable(recipe) && recipe.steps !== "auto" ? recipe : null;

  function patch(p: Partial<WebLoginRecipe>) {
    if (!recipe) return;
    emit({ ...recipe, ...p });
  }

  function patchStep(i: number, s: WebRecipeStep) {
    if (!explicit) return;
    patch({ steps: (explicit.steps as WebRecipeStep[]).map((x, j) => (j === i ? s : x)) });
  }

  function addStep() {
    if (!explicit || !baseOrigin) return;
    const steps = explicit.steps as WebRecipeStep[];
    patch({
      steps: [...steps, { when_url: `${baseOrigin}/`, actions: [{ wait: "body" }] }],
    });
  }

  const structuredOk = recipe !== undefined && drawable(recipe);

  return (
    <div className="space-y-3 min-w-0">
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] p-2 text-xs text-[var(--color-text-muted)]">
        <strong className="text-[var(--color-text)]">How a form login works.</strong> Each step names a
        page (a URL pattern on this profile&rsquo;s origins) and the fields to fill or buttons to
        press there. The credential is filled into the page&rsquo;s own form and submitted; the
        operator never sees it. A recipe is data, never script.
      </div>

      {/* Starting points */}
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 sm:col-span-1 min-w-0">
          <Select
            label="Start from"
            value={presetId}
            onChange={(e) => setPresetId(e.target.value)}
            options={[
              { value: "", label: "(choose a starting point)" },
              { value: "__blank", label: "Blank recipe (username, password, submit)" },
              { value: "__auto", label: "Heuristic (find fields automatically; policy-gated)" },
              ...WEB_RECIPE_PRESETS.map((p) => ({ value: p.id, label: presetLabel(p) })),
            ]}
          />
        </div>
        <div className="col-span-2 sm:col-span-1 flex items-end gap-2">
          <Button size="sm" variant="secondary" disabled={!presetId || !baseOrigin} onClick={applyStart}>
            {recipe ? "Replace recipe" : "Use this"}
          </Button>
          {!baseOrigin && (
            <span className="text-xs text-[var(--color-text-muted)]">Enter a valid start URL first.</span>
          )}
        </div>
        {presetId && presetId !== "__blank" && presetId !== "__auto" && findPreset(presetId) && (
          <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
            <strong className="text-[var(--color-warning,var(--color-text))]">
              Unverified against a live appliance.
            </strong>{" "}
            {findPreset(presetId)!.note}
          </p>
        )}
        {presetId === "__auto" && (
          <p className="col-span-2 text-xs text-[var(--color-text-muted)]">
            Heuristic mode finds the login fields by their <code>autocomplete</code> attributes. It can
            fill the wrong field, so the server refuses it unless the resource type (or the resource) sets
            &ldquo;allow heuristic fill&rdquo;.
          </p>
        )}
      </div>

      {appliedPreset && (
        <p
          className="rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2 text-xs"
          data-testid="preset-unverified"
        >
          <strong>{findPreset(appliedPreset)?.label ?? appliedPreset} preset: unverified against a live
          appliance.</strong>{" "}
          It was written from the vendor&rsquo;s documented login form, not recorded from a real device.
          Press &ldquo;Test recipe&rdquo; against yours and adjust the selectors and the success and failure
          conditions.
        </p>
      )}

      {/* Import / export */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          className="hidden"
          data-testid="recipe-file-input"
          onChange={(e) => void onFile(e.target.files?.[0])}
        />
        <Button size="sm" variant="ghost" onClick={() => fileRef.current?.click()}>
          Import file
        </Button>
        <Button size="sm" variant="ghost" onClick={() => void pasteFromClipboard()}>
          Paste from clipboard
        </Button>
        <Button size="sm" variant="ghost" disabled={!recipe} onClick={() => void copyJson()}>
          Copy JSON
        </Button>
        <Button size="sm" variant="ghost" disabled={!recipe} onClick={downloadJson}>
          Download JSON
        </Button>
        <div className="ml-auto flex gap-1">
          <Button
            size="sm"
            variant={view === "structured" ? "secondary" : "ghost"}
            onClick={() => setView("structured")}
          >
            Steps
          </Button>
          <Button size="sm" variant={view === "json" ? "secondary" : "ghost"} onClick={() => setView("json")}>
            JSON
          </Button>
        </div>
      </div>
      {notice && (
        <p
          role={notice.kind === "error" ? "alert" : "status"}
          className={`text-xs ${notice.kind === "error" ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}
        >
          {notice.text}
        </p>
      )}

      {/* Raw view */}
      {view === "json" && (
        <div>
          <Textarea
            label="Recipe JSON"
            rows={14}
            value={jsonText}
            onChange={(e) => onJsonEdit(e.target.value)}
            spellCheck={false}
            placeholder={'{\n  "version": 1,\n  "steps": [ ... ],\n  "success_when": { "url": "https://app.example.com/home*" }\n}'}
            error={jsonError ?? undefined}
          />
        </div>
      )}

      {/* Structured view */}
      {view === "structured" && recipe === undefined && (
        <p className="text-xs text-[var(--color-text-muted)]">
          No recipe yet. Pick a starting point above, import a recipe, or paste JSON in the JSON view.
        </p>
      )}
      {view === "structured" && recipe !== undefined && !structuredOk && (
        <p className="text-xs text-[var(--color-danger)]">
          This recipe is not shaped like a recipe the step editor can draw. Fix it in the JSON view.
        </p>
      )}
      {view === "structured" && recipe !== undefined && structuredOk && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Fill mode"
              value={isHeuristicRecipe(recipe) ? "auto" : "steps"}
              onChange={(e) => {
                if (!baseOrigin) return;
                if (e.target.value === "auto") {
                  patch({ steps: "auto" });
                } else {
                  patch({
                    steps: (blankRecipe(baseOrigin).steps as WebRecipeStep[]),
                  });
                }
              }}
              options={[
                { value: "steps", label: "Explicit steps" },
                { value: "auto", label: "Heuristic (policy-gated)" },
              ]}
            />
            <Select
              label="Vendor label"
              value={recipe.vendor ?? ""}
              onChange={(e) => {
                const { vendor: _v, ...rest } = recipe;
                void _v;
                emit(e.target.value ? { ...rest, vendor: e.target.value } : (rest as WebLoginRecipe));
              }}
              options={[
                { value: "", label: "(none)" },
                ...WEB_RECIPE_VENDORS.map((v) => ({ value: v, label: v })),
              ]}
            />
          </div>

          {isHeuristicRecipe(recipe) && (
            <p className="text-xs text-[var(--color-text-muted)]">
              Heuristic mode finds the username, password and one-time-code fields by their{" "}
              <code>autocomplete</code> attributes (falling back to a single password field) and submits the
              form of the last field it filled. More than one candidate aborts the login. It is off unless
              the resource type or the resource enables it.
            </p>
          )}

          {explicit &&
            (explicit.steps as WebRecipeStep[]).map((s, si) => (
              <div key={si} className="rounded-lg border border-[var(--color-border)] p-3 space-y-2 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Step {si + 1}</span>
                  <div className="ml-auto flex gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Move step ${si + 1} up`}
                      disabled={si === 0}
                      onClick={() => patch({ steps: move(explicit.steps as WebRecipeStep[], si, si - 1) })}
                    >
                      &uarr;
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Move step ${si + 1} down`}
                      disabled={si === (explicit.steps as WebRecipeStep[]).length - 1}
                      onClick={() => patch({ steps: move(explicit.steps as WebRecipeStep[], si, si + 1) })}
                    >
                      &darr;
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Remove step ${si + 1}`}
                      disabled={(explicit.steps as WebRecipeStep[]).length <= 1}
                      onClick={() =>
                        patch({ steps: (explicit.steps as WebRecipeStep[]).filter((_, j) => j !== si) })
                      }
                    >
                      Remove
                    </Button>
                  </div>
                </div>
                <Input
                  label={`Step ${si + 1}: runs when the page URL matches`}
                  value={s.when_url}
                  onChange={(e) => patchStep(si, { ...s, when_url: e.target.value })}
                  placeholder="https://fw01.example.com/login*"
                  hint="Full URL on one of this profile's origins. Only * is special, and only after the host."
                />
                <div className="space-y-2">
                  {s.actions.map((a, ai) => {
                    const verb = verbOf(a);
                    const fillValue = "fill" in a ? a.value : "";
                    const kind = "fill" in a ? fillKindOf(fillValue) : null;
                    const setAction = (next: WebRecipeAction) =>
                      patchStep(si, { ...s, actions: s.actions.map((x, j) => (j === ai ? next : x)) });
                    return (
                      <div key={ai} className="grid grid-cols-12 gap-2 items-end">
                        <div className="col-span-12 sm:col-span-2 min-w-0">
                          <Select
                            label={ai === 0 ? "Action" : undefined}
                            aria-label={`Step ${si + 1} action ${ai + 1} verb`}
                            value={verb}
                            onChange={(e) => setAction(withVerb(a, e.target.value as Verb))}
                            options={[
                              { value: "fill", label: "fill" },
                              { value: "click", label: "click" },
                              { value: "submit", label: "submit" },
                              { value: "wait", label: "wait for" },
                            ]}
                          />
                        </div>
                        <div className="col-span-12 sm:col-span-4 min-w-0">
                          <Input
                            label={ai === 0 ? "CSS selector" : undefined}
                            aria-label={`Step ${si + 1} action ${ai + 1} selector`}
                            value={selectorOf(a)}
                            onChange={(e) => setAction(withSelector(a, e.target.value))}
                            placeholder="input[name=username]"
                            className="font-mono"
                          />
                        </div>
                        <div className="col-span-8 sm:col-span-4 min-w-0">
                          {kind !== null && (
                            <div className="flex gap-2">
                              <div className="min-w-0 flex-1">
                                <Select
                                  label={ai === 0 ? "Value" : undefined}
                                  aria-label={`Step ${si + 1} action ${ai + 1} value`}
                                  value={kind}
                                  onChange={(e) => {
                                    const k = e.target.value as FillKind;
                                    setAction({
                                      fill: selectorOf(a),
                                      value: k === "literal" ? "literal:" : k,
                                    });
                                  }}
                                  options={[
                                    { value: "username", label: "username" },
                                    { value: "password", label: "password" },
                                    { value: "totp", label: "TOTP code" },
                                    { value: "literal", label: "fixed text" },
                                  ]}
                                />
                              </div>
                              {kind === "literal" && (
                                <div className="min-w-0 flex-1">
                                  <Input
                                    label={ai === 0 ? "Text" : undefined}
                                    aria-label={`Step ${si + 1} action ${ai + 1} literal text`}
                                    value={fillValue.slice("literal:".length)}
                                    onChange={(e) =>
                                      setAction({ fill: selectorOf(a), value: `literal:${e.target.value}` })
                                    }
                                    placeholder="non-secret"
                                  />
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                        <div className="col-span-4 sm:col-span-2 flex gap-1 justify-end">
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-label={`Move step ${si + 1} action ${ai + 1} up`}
                            disabled={ai === 0}
                            onClick={() => patchStep(si, { ...s, actions: move(s.actions, ai, ai - 1) })}
                          >
                            &uarr;
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-label={`Move step ${si + 1} action ${ai + 1} down`}
                            disabled={ai === s.actions.length - 1}
                            onClick={() => patchStep(si, { ...s, actions: move(s.actions, ai, ai + 1) })}
                          >
                            &darr;
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            aria-label={`Remove step ${si + 1} action ${ai + 1}`}
                            disabled={s.actions.length <= 1}
                            onClick={() => patchStep(si, { ...s, actions: s.actions.filter((_, j) => j !== ai) })}
                          >
                            &times;
                          </Button>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={s.actions.length >= MAX_ACTIONS_PER_STEP}
                  onClick={() => patchStep(si, { ...s, actions: [...s.actions, { click: "" }] })}
                >
                  + Add action
                </Button>
              </div>
            ))}
          {explicit && (
            <Button
              size="sm"
              variant="ghost"
              disabled={(explicit.steps as WebRecipeStep[]).length >= MAX_STEPS || !baseOrigin}
              onClick={addStep}
            >
              + Add step
            </Button>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 sm:col-span-1 min-w-0 space-y-2">
              <p className="text-sm font-medium text-[var(--color-text-muted)]">Success when</p>
              <Input
                aria-label="Success URL pattern"
                value={recipe.success_when.url ?? ""}
                onChange={(e) => patch({ success_when: dropEmpty({ ...recipe.success_when, url: e.target.value }) })}
                placeholder="URL pattern, e.g. https://fw01.example.com/ng/*"
              />
              <Input
                aria-label="Success selector"
                value={recipe.success_when.selector ?? ""}
                onChange={(e) =>
                  patch({ success_when: dropEmpty({ ...recipe.success_when, selector: e.target.value }) })
                }
                placeholder="or a CSS selector that appears when signed in"
                className="font-mono"
              />
            </div>
            <div className="col-span-2 sm:col-span-1 min-w-0 space-y-2">
              <label className="flex items-center gap-2 text-sm font-medium text-[var(--color-text-muted)]">
                <input
                  type="checkbox"
                  checked={recipe.failure_when !== undefined}
                  onChange={(e) => {
                    const { failure_when: _f, ...rest } = recipe;
                    void _f;
                    emit(
                      e.target.checked
                        ? { ...rest, failure_when: { selector: ".error" } }
                        : (rest as WebLoginRecipe),
                    );
                  }}
                />
                Failure when
              </label>
              {recipe.failure_when !== undefined && (
                <>
                  <Input
                    aria-label="Failure URL pattern"
                    value={recipe.failure_when.url ?? ""}
                    onChange={(e) =>
                      patch({ failure_when: dropEmpty({ ...recipe.failure_when, url: e.target.value }) })
                    }
                    placeholder="URL pattern, e.g. https://jenkins.example.com/loginError*"
                  />
                  <Input
                    aria-label="Failure selector"
                    value={recipe.failure_when.selector ?? ""}
                    onChange={(e) =>
                      patch({ failure_when: dropEmpty({ ...recipe.failure_when, selector: e.target.value }) })
                    }
                    placeholder="or a CSS selector for the error message"
                    className="font-mono"
                  />
                </>
              )}
            </div>
            <Input
              label="Timeout (seconds)"
              type="number"
              value={recipe.timeout_secs?.toString() ?? ""}
              onChange={(e) => {
                const { timeout_secs: _t, ...rest } = recipe;
                void _t;
                emit(
                  e.target.value === ""
                    ? (rest as WebLoginRecipe)
                    : { ...rest, timeout_secs: Number(e.target.value) },
                );
              }}
              placeholder="30"
              hint={`1–${MAX_TIMEOUT_SECS}, default 30`}
            />
            <div className="min-w-0">
              <p className="mb-1 text-sm font-medium text-[var(--color-text-muted)]">Wait for the operator</p>
              {(["captcha", "push_mfa"] as const).map((reason) => (
                <label key={reason} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={(recipe.pause_for_operator ?? []).includes(reason)}
                    onChange={(e) => {
                      const cur = recipe.pause_for_operator ?? [];
                      const next = e.target.checked ? [...cur, reason] : cur.filter((r) => r !== reason);
                      const { pause_for_operator: _p, ...rest } = recipe;
                      void _p;
                      emit(next.length > 0 ? { ...rest, pause_for_operator: next } : (rest as WebLoginRecipe));
                    }}
                  />
                  {reason === "captcha" ? "A CAPTCHA to solve" : "A push-MFA approval"}
                </label>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Verdict */}
      {recipe !== undefined && (
        <p
          className={`text-xs min-w-0 break-words ${problem ? "text-[var(--color-danger)]" : "text-[var(--color-text-muted)]"}`}
          role={problem ? "alert" : undefined}
          data-testid="recipe-verdict"
        >
          {problem ?? "The recipe passes the server's validation."}
        </p>
      )}

      {/* Dry run */}
      <div className="rounded-lg border border-[var(--color-border)] p-3 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" disabled={!canTest} loading={testing} onClick={() => void runTest()}>
            Test recipe
          </Button>
          <span className="text-xs text-[var(--color-text-muted)]">
            Opens the start URL in a test window and checks that each field, button and condition can be
            found.
          </span>
        </div>
        <p className="text-xs text-[var(--color-text-muted)]" data-testid="recipe-test-safety">
          <strong className="text-[var(--color-text)]">Sends no credential and submits nothing.</strong> The
          test only reads the page: no username, password or code is filled, no button is clicked and no form
          is posted, and the vault is not asked for a secret. Pages after the first (a TOTP page, say) are
          checked as you sign in by hand in the test window.
        </p>
        {testError && (
          <p role="alert" className="text-xs text-[var(--color-danger)]">
            {testError}
          </p>
        )}
        {testResult && <WebRecipeTestReport result={testResult} />}
      </div>
    </div>
  );
}

/** A condition with an empty `url` or `selector` drops that key, so the
 *  field being cleared reads as "absent" to the validator rather than as an
 *  empty string. */
function dropEmpty(c: { url?: string; selector?: string }): { url?: string; selector?: string } {
  const out: { url?: string; selector?: string } = {};
  if (c.url !== undefined && c.url !== "") out.url = c.url;
  if (c.selector !== undefined && c.selector !== "") out.selector = c.selector;
  return out;
}
