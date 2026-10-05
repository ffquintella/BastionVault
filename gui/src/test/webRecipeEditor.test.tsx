/**
 * Web Application Connect, Phase 2: the form-mode profile fields, the recipe
 * editor (presets, JSON view, import / export, dry run), the exposure notice
 * and the Settings → Resource Types policy controls.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { useState } from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => {}),
  emit: () => Promise.resolve(),
}));

import { WebProfileFields } from "../components/WebProfileFields";
import { TypeEditorModal } from "../routes/SettingsPage";
import { DEFAULT_RESOURCE_TYPES, heuristicChoice, webExposureChoice, withWebPolicy } from "../lib/resourceTypes";
import { WEB_RECIPE_PRESETS } from "../lib/webRecipePresets";
import { validateWebRecipe } from "../lib/webRecipe";
import type { ResourceTypeDef, WebProfileSettings } from "../lib/types";

const START = "https://fw01.example.com/login";

const DOM_TYPES = { web_application: { ...DEFAULT_RESOURCE_TYPES.web_application } };

function Harness({
  initial,
  resource = { type: "web_application" },
  onWeb,
  onTextError,
}: {
  initial?: Partial<WebProfileSettings>;
  resource?: Record<string, unknown>;
  onWeb?: (w: WebProfileSettings) => void;
  onTextError?: (m: string | null) => void;
}) {
  const [web, setWeb] = useState<WebProfileSettings>({
    start_url: START,
    allowed_origins: [],
    login_mode: "form",
    ...initial,
  });
  return (
    <MemoryRouter>
      <WebProfileFields
        web={web}
        onChange={(w) => {
          setWeb(w);
          onWeb?.(w);
        }}
        resource={resource}
        onRecipeTextError={onTextError}
      />
    </MemoryRouter>
  );
}

function mockTypes(saved: unknown, extra: (cmd: string, args: unknown) => unknown = () => undefined) {
  mockInvoke.mockImplementation((cmd: string, args: unknown) => {
    const e = extra(cmd, args);
    if (e !== undefined) return e;
    if (cmd === "resource_types_read") {
      return saved instanceof Error ? Promise.reject(saved) : Promise.resolve(saved);
    }
    return Promise.reject(new Error(`unexpected invoke ${cmd}`));
  });
}

beforeEach(() => {
  mockInvoke.mockReset();
});

describe("exposure notice — mirrors the server's deny-by-default", () => {
  it("warns, with a Settings link, when the saved config does not opt the type in", async () => {
    mockTypes(null);
    render(<Harness />);
    const alert = await screen.findByTestId("exposure-refused");
    expect(alert).toHaveTextContent(/server will refuse/i);
    expect(alert).toHaveTextContent("exposure_not_permitted");
    const link = within(alert).getByRole("link", { name: /Settings/ });
    expect(link).toHaveAttribute("href", "/settings");
  });

  it("warns when the type is saved without a cap, and when the cap is below dom", async () => {
    mockTypes({ web_application: { id: "web_application", label: "W", fields: [], connect: { protocols: ["web"] } } });
    const { unmount } = render(<Harness />);
    expect((await screen.findByTestId("exposure-refused")).textContent).toMatch(/does not set/);
    unmount();

    mockTypes({ web_application: { ...DOM_TYPES.web_application, connect: { web_exposure_max: "proxy" } } });
    render(<Harness />);
    expect((await screen.findByTestId("exposure-refused")).textContent).toMatch(/caps web exposure at `proxy`/);
  });

  it("reads the saved config, never the builtins the GUI merges in", async () => {
    // The builtin web_application carries `dom` in the GUI, but nothing was
    // saved: the server would deny, and so does the notice.
    expect(DEFAULT_RESOURCE_TYPES.web_application.connect?.web_exposure_max).toBe("dom");
    mockTypes(null);
    render(<Harness />);
    expect(await screen.findByTestId("exposure-refused")).toBeInTheDocument();
  });

  it("is quiet and says so when the saved type opts in", async () => {
    mockTypes(DOM_TYPES);
    render(<Harness />);
    expect(await screen.findByTestId("exposure-ok")).toHaveTextContent(/exposure cap/);
    expect(screen.queryByTestId("exposure-refused")).toBeNull();
  });

  it("applies the resource tier and the heuristic rule", async () => {
    mockTypes(DOM_TYPES);
    render(<Harness resource={{ type: "web_application", web_exposure_max: "none" }} />);
    expect((await screen.findByTestId("exposure-refused")).textContent).toMatch(/resource tier caps/);
  });

  it("says it can't tell when the config can't be read, rather than guessing", async () => {
    mockTypes(new Error("403 forbidden"));
    render(<Harness />);
    expect(await screen.findByTestId("exposure-unknown")).toHaveTextContent(/can.t tell/);
    expect(screen.queryByTestId("exposure-refused")).toBeNull();
  });

  it("does not read the config for open mode", async () => {
    mockTypes(null);
    render(<Harness initial={{ login_mode: "open" }} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(mockInvoke).not.toHaveBeenCalled();
    expect(screen.queryByTestId("exposure-refused")).toBeNull();
  });
});

describe("recipe editor — presets", () => {
  it("applies each preset onto the start URL's origin and marks it unverified", async () => {
    mockTypes(DOM_TYPES);
    const user = userEvent.setup();
    let latest: WebProfileSettings | undefined;
    render(<Harness onWeb={(w) => (latest = w)} />);
    const picker = screen.getByLabelText("Start from");
    // Every option that names a vendor carries the caveat.
    const labels = Array.from((picker as HTMLSelectElement).options).map((o) => o.textContent ?? "");
    for (const p of WEB_RECIPE_PRESETS) {
      expect(labels.some((l) => l.includes(p.label) && /unverified against a live appliance/.test(l)), p.id).toBe(true);
    }

    for (const p of WEB_RECIPE_PRESETS) {
      await user.selectOptions(picker, p.id);
      expect(screen.getByText(/Unverified against a live appliance\./)).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: /use this|replace recipe/i }));
      expect(latest?.recipe, p.id).toBeDefined();
      expect(latest?.recipe).toMatchObject({ vendor: p.id });
      expect(validateWebRecipe(latest?.recipe).ok, p.id).toBe(true);
      expect(JSON.stringify(latest?.recipe)).toContain("https://fw01.example.com");
      expect(screen.getByTestId("preset-unverified")).toHaveTextContent(/unverified against a live appliance/);
      expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/passes the server's validation/);
    }
  });

  it("needs a valid start URL before offering a preset", async () => {
    mockTypes(DOM_TYPES);
    render(<Harness initial={{ start_url: "not a url" }} />);
    expect(screen.getByText(/Enter a valid start URL first/)).toBeInTheDocument();
    await userEvent.setup().selectOptions(screen.getByLabelText("Start from"), "fortigate");
    expect(screen.getByRole("button", { name: /use this/i })).toBeDisabled();
  });

  it("starts a heuristic recipe and says it is policy-gated", async () => {
    mockTypes(DOM_TYPES);
    const user = userEvent.setup();
    let latest: WebProfileSettings | undefined;
    render(<Harness onWeb={(w) => (latest = w)} />);
    await user.selectOptions(screen.getByLabelText("Start from"), "__auto");
    await user.click(screen.getByRole("button", { name: /use this/i }));
    expect(latest?.recipe?.steps).toBe("auto");
    // The type opted in to dom but not to heuristics.
    expect((await screen.findByTestId("exposure-refused")).textContent).toMatch(/heuristic/);
  });
});

describe("recipe editor — structured edits and validation messages", () => {
  async function withBlank() {
    mockTypes(DOM_TYPES);
    const user = userEvent.setup();
    let latest: WebProfileSettings | undefined;
    render(<Harness onWeb={(w) => (latest = w)} />);
    await user.selectOptions(screen.getByLabelText("Start from"), "__blank");
    await user.click(screen.getByRole("button", { name: /use this/i }));
    return { user, get: () => latest! };
  }

  it("edits a selector and reports a server-worded error naming the field", async () => {
    const { user } = await withBlank();
    const sel = screen.getByLabelText("Step 1 action 1 selector");
    await user.clear(sel);
    const verdict = screen.getByTestId("recipe-verdict");
    expect(verdict).toHaveTextContent(/recipe `steps\[0\]\.actions\[0\]\.fill`: must not be empty/);
    await user.type(sel, "input#u");
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/passes/);
  });

  it("switches an action's verb and a fill's value, and adds a literal", async () => {
    const { user, get } = await withBlank();
    await user.selectOptions(screen.getByLabelText("Step 1 action 3 verb"), "wait");
    expect((get().recipe!.steps as { actions: unknown[] }[])[0].actions[2]).toEqual({ wait: "button[type=submit]" });
    await user.selectOptions(screen.getByLabelText("Step 1 action 1 value"), "literal");
    // An empty literal is refused until it has text.
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/steps\[0\]\.actions\[0\]\.value/);
    await user.type(screen.getByLabelText("Step 1 action 1 literal text"), "CORP");
    expect((get().recipe!.steps as { actions: unknown[] }[])[0].actions[0]).toEqual({
      fill: "input[name=username]",
      value: "literal:CORP",
    });
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/passes/);
  });

  it("refuses a step whose URL is off the profile's origins", async () => {
    const { user } = await withBlank();
    const url = screen.getByLabelText(/Step 1: runs when/);
    await user.clear(url);
    await user.type(url, "https://evil.example.net/login*");
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/steps\[0\]\.when_url.*origin is not/);
    // The dry run is not offered for a recipe the server would refuse.
    expect(screen.getByRole("button", { name: "Test recipe" })).toBeDisabled();
  });

  it("holds the timeout to 1-60", async () => {
    const { user } = await withBlank();
    const t = screen.getByLabelText("Timeout (seconds)");
    await user.clear(t);
    await user.type(t, "61");
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/timeout_secs.*1\.\.=60/);
    await user.clear(t);
    await user.type(t, "60");
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/passes/);
  });

  it("adds and removes steps and actions, keeping at least one of each", async () => {
    const { user, get } = await withBlank();
    await user.click(screen.getByRole("button", { name: "+ Add step" }));
    expect((get().recipe!.steps as unknown[]).length).toBe(2);
    expect(screen.getByRole("button", { name: "Remove step 1" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Remove step 2" }));
    expect((get().recipe!.steps as unknown[]).length).toBe(1);
    expect(screen.getByRole("button", { name: "Remove step 1" })).toBeDisabled();
  });
});

describe("recipe editor — JSON view, import and export", () => {
  async function inJsonView() {
    mockTypes(DOM_TYPES);
    const user = userEvent.setup();
    let latest: WebProfileSettings | undefined;
    const errors: (string | null)[] = [];
    render(<Harness onWeb={(w) => (latest = w)} onTextError={(m) => errors.push(m)} />);
    await user.click(screen.getByRole("button", { name: "JSON" }));
    return { user, get: () => latest, errors };
  }

  const GOOD = JSON.stringify({
    version: 1,
    steps: [{ when_url: "https://fw01.example.com/login*", actions: [{ fill: "#u", value: "username" }] }],
    success_when: { url: "https://fw01.example.com/home*" },
  });

  it("applies valid JSON and reports unparseable text to the parent", async () => {
    const { get, errors } = await inJsonView();
    const box = screen.getByLabelText("Recipe JSON");
    fireEvent.change(box, { target: { value: "{ nope" } });
    expect(errors[errors.length - 1]).toMatch(/not valid JSON/);
    expect(get()?.recipe).toBeUndefined();
    fireEvent.change(box, { target: { value: GOOD } });
    expect(errors[errors.length - 1]).toBeNull();
    expect(get()?.recipe).toMatchObject({ version: 1 });
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/passes/);
  });

  it("clears a pending text error when the editor goes away, so Save isn't held for nothing", async () => {
    mockTypes(DOM_TYPES);
    const errors: (string | null)[] = [];
    const user = userEvent.setup();
    const { unmount } = render(<Harness onTextError={(m) => errors.push(m)} />);
    await user.click(screen.getByRole("button", { name: "JSON" }));
    fireEvent.change(screen.getByLabelText("Recipe JSON"), { target: { value: "{" } });
    expect(errors[errors.length - 1]).toMatch(/not valid JSON/);
    unmount();
    expect(errors[errors.length - 1]).toBeNull();
  });

  it("surfaces a strict-validation error for parseable but invalid JSON", async () => {
    const { get } = await inJsonView();
    fireEvent.change(screen.getByLabelText("Recipe JSON"), {
      target: { value: JSON.stringify({ version: 1, steps: "auto", success_when: { selector: "x" }, on_load: "alert(1)" }) },
    });
    expect(get()?.recipe).toBeDefined();
    expect(screen.getByTestId("recipe-verdict")).toHaveTextContent(/recipe `on_load`: is not a recipe field/);
  });

  it("imports a file through the strict reader and refuses a hostile one", async () => {
    const { get } = await inJsonView();
    const input = screen.getByTestId("recipe-file-input");
    const good = new File([GOOD], "recipe.json", { type: "application/json" });
    fireEvent.change(input, { target: { files: [good] } });
    await waitFor(() => expect(get()?.recipe).toMatchObject({ version: 1 }));
    expect(screen.getByRole("status")).toHaveTextContent(/Imported a recipe from file recipe\.json/);

    const before = get()?.recipe;
    const bad = new File(['{"version":1,"steps":"auto","success_when":{"selector":"x"},"__proto__":{"a":1}}'], "bad.json");
    fireEvent.change(input, { target: { files: [bad] } });
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/Import from file bad\.json refused/));
    expect(get()?.recipe).toBe(before);
    const junk = new File(["<script>alert(1)</script>"], "x.json");
    fireEvent.change(input, { target: { files: [junk] } });
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/not valid JSON/));
    expect(get()?.recipe).toBe(before);
  });

  it("imports from the clipboard and refuses a bad version", async () => {
    const { user, get } = await inJsonView();
    const read = vi.fn().mockResolvedValue(GOOD);
    Object.defineProperty(navigator, "clipboard", { value: { readText: read, writeText: vi.fn() }, configurable: true });
    await user.click(screen.getByRole("button", { name: "Paste from clipboard" }));
    await waitFor(() => expect(get()?.recipe).toMatchObject({ version: 1 }));
    read.mockResolvedValue(JSON.stringify({ version: 9, steps: "auto", success_when: { selector: "x" } }));
    await user.click(screen.getByRole("button", { name: "Paste from clipboard" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/version 9 is not supported/));
  });

  it("copies the recipe JSON to the clipboard", async () => {
    const { user } = await inJsonView();
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { readText: vi.fn(), writeText: write }, configurable: true });
    expect(screen.getByRole("button", { name: "Copy JSON" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Recipe JSON"), { target: { value: GOOD } });
    await user.click(screen.getByRole("button", { name: "Copy JSON" }));
    await waitFor(() => expect(write).toHaveBeenCalled());
    expect(JSON.parse(write.mock.calls[0][0] as string)).toEqual(JSON.parse(GOOD));
  });
});

describe("recipe editor — Test recipe (dry run)", () => {
  const REPORT = {
    recipe_hash: "sha256:" + "ab".repeat(32),
    report: {
      outcome: "complete",
      heuristic: false,
      steps: [
        {
          index: 0,
          reached: true,
          origin: "https://fw01.example.com",
          actions: [
            { index: 0, kind: "fill", value: "username", status: "ok", matches: 1 },
            { index: 1, kind: "fill", value: "password", status: "ambiguous", matches: 2 },
            { index: 2, kind: "click", value: null, status: "no_match", matches: 0 },
          ],
        },
        { index: 1, reached: false, origin: null, actions: [{ index: 0, kind: "fill", value: "totp", status: "not_reached", matches: null }] },
      ],
      heuristic_check: null,
      origins_seen: ["https://fw01.example.com"],
      success_seen: false,
      failure_seen: false,
    },
  };

  it("says it sends no credential, calls the host with no credential, and renders the report", async () => {
    mockTypes(DOM_TYPES, (cmd) => (cmd === "web_recipe_test" ? Promise.resolve(REPORT) : undefined));
    const user = userEvent.setup();
    render(<Harness initial={{ allowed_origins: ["https://sso.example.com"] }} />);
    expect(screen.getByTestId("recipe-test-safety")).toHaveTextContent(/Sends no credential and submits nothing/);
    expect(screen.getByRole("button", { name: "Test recipe" })).toBeDisabled(); // no recipe yet
    await user.selectOptions(screen.getByLabelText("Start from"), "fortigate");
    await user.click(screen.getByRole("button", { name: /use this/i }));
    await user.click(screen.getByRole("button", { name: "Test recipe" }));

    const report = await screen.findByTestId("recipe-test-report");
    expect(report).toHaveTextContent("Outcome: complete");
    expect(report).toHaveTextContent("1 match");
    expect(report).toHaveTextContent("2 matches");
    expect(report).toHaveTextContent("0 matches");
    expect(report).toHaveTextContent(/More than one element matches/);
    expect(report).toHaveTextContent(/not reached/);
    expect(report).toHaveTextContent(REPORT.recipe_hash);

    const call = mockInvoke.mock.calls.find((c) => c[0] === "web_recipe_test");
    expect(call).toBeDefined();
    const request = (call![1] as { request: Record<string, unknown> }).request;
    expect(Object.keys(request).sort()).toEqual(["allow_insecure_http", "allowed_origins", "recipe", "url"]);
    expect(request.url).toBe(START);
    expect(request.allowed_origins).toEqual(["https://sso.example.com"]);
    // Nothing that could carry a credential, and no vault call besides the type read.
    expect(JSON.stringify(request)).not.toMatch(/password":|totp_code|secret_id/);
    expect(mockInvoke.mock.calls.map((c) => c[0])).toEqual(["resource_types_read", "web_recipe_test"]);
  });

  it("shows the host's error when the test cannot run", async () => {
    mockTypes(DOM_TYPES, (cmd) => (cmd === "web_recipe_test" ? Promise.reject(new Error("a web or RDP session is already live")) : undefined));
    const user = userEvent.setup();
    render(<Harness />);
    await user.selectOptions(screen.getByLabelText("Start from"), "jenkins");
    await user.click(screen.getByRole("button", { name: /use this/i }));
    await user.click(screen.getByRole("button", { name: "Test recipe" }));
    expect(await screen.findByText(/already live/)).toBeInTheDocument();
  });
});

describe("Settings → Resource Types: web exposure policy controls", () => {
  const webType: ResourceTypeDef = {
    id: "my_console",
    label: "My console",
    color: "info",
    fields: [],
    connect: { protocols: ["web"] },
  };

  function renderEditor(typeDef: ResourceTypeDef | null) {
    const onSave = vi.fn();
    render(<TypeEditorModal typeDef={typeDef} onSave={onSave} onClose={() => {}} />);
    return onSave;
  }

  it("shows the controls only on types that offer web, defaulting to unset (denied)", () => {
    renderEditor({ ...DEFAULT_RESOURCE_TYPES.database });
    expect(screen.queryByTestId("web-policy")).toBeNull();
    // A fresh web type starts unset.
    expect(webExposureChoice(webType.connect)).toBe("");
    expect(heuristicChoice(webType.connect)).toBe("");
  });

  it("saves the cap and the heuristic flag onto connect, and round-trips them", async () => {
    const user = userEvent.setup();
    const onSave = renderEditor(webType);
    expect(screen.getByLabelText("Web exposure cap")).toHaveValue("");
    await user.selectOptions(screen.getByLabelText("Web exposure cap"), "dom");
    await user.selectOptions(screen.getByLabelText("Allow heuristic fill"), "true");
    await user.click(screen.getByRole("button", { name: "Save" }));
    const saved = onSave.mock.calls[0][0] as ResourceTypeDef;
    expect(saved.connect).toMatchObject({ protocols: ["web"], web_exposure_max: "dom", allow_heuristic_fill: true });

    // Reopen with what was saved: the controls show it, and saving again changes nothing.
    document.body.innerHTML = "";
    const again = renderEditor(saved);
    expect(screen.getByLabelText("Web exposure cap")).toHaveValue("dom");
    expect(screen.getByLabelText("Allow heuristic fill")).toHaveValue("true");
    await userEvent.setup().click(screen.getByRole("button", { name: "Save" }));
    expect(again.mock.calls[0][0]).toEqual(saved);
  });

  it("removes the keys again when set back to unset, and writes an explicit false", async () => {
    const user = userEvent.setup();
    const onSave = renderEditor({
      ...webType,
      connect: { protocols: ["web"], web_exposure_max: "dom", allow_heuristic_fill: true },
    });
    await user.selectOptions(screen.getByLabelText("Web exposure cap"), "");
    await user.selectOptions(screen.getByLabelText("Allow heuristic fill"), "false");
    await user.click(screen.getByRole("button", { name: "Save" }));
    const connect = (onSave.mock.calls[0][0] as ResourceTypeDef).connect!;
    expect(connect).not.toHaveProperty("web_exposure_max");
    expect(connect.allow_heuristic_fill).toBe(false);
  });

  it("keeps a saved value it does not recognise untouched", async () => {
    const odd = { ...webType, connect: { protocols: ["web"], web_exposure_max: "everything" } } as unknown as ResourceTypeDef;
    expect(webExposureChoice(odd.connect)).toBe("keep");
    const onSave = renderEditor(odd);
    expect(screen.getByLabelText("Web exposure cap")).toHaveValue("keep");
    await userEvent.setup().click(screen.getByRole("button", { name: "Save" }));
    expect((onSave.mock.calls[0][0] as ResourceTypeDef).connect).toMatchObject({ web_exposure_max: "everything" });
  });

  it("withWebPolicy only touches the two policy keys", () => {
    const base = { enabled: false, protocols: ["web" as const], default_ports: { ssh: 2222 } };
    expect(withWebPolicy(base, "dom", "")).toEqual({ ...base, web_exposure_max: "dom" });
    expect(withWebPolicy({ ...base, web_exposure_max: "dom" }, "", "false")).toEqual({
      ...base,
      allow_heuristic_fill: false,
    });
    expect(withWebPolicy({ ...base, web_exposure_max: "dom", allow_heuristic_fill: true }, "keep", "keep")).toEqual({
      ...base,
      web_exposure_max: "dom",
      allow_heuristic_fill: true,
    });
  });
});
