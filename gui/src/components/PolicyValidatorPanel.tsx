import { useEffect, useState } from "react";
import { Button, Card, Input, Select, Badge, CollapsibleSection } from "./ui";
import { parsePolicyHcl, lintPolicyModel, CAPABILITIES, type LintFinding } from "../lib/policyHcl";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import type { PolicyTestCase, PolicyTestResultRow } from "../lib/types";

interface Props {
  /** Policy name (used to persist test cases). */
  name: string;
  /** Current draft HCL to validate and test against. */
  hcl: string;
  /** Saved test cases loaded from the backend. */
  savedCases: PolicyTestCase[];
  /** Called after the cases are (re)saved so the parent can refresh. */
  onSavedCasesChange: (cases: PolicyTestCase[]) => void;
  toast: (kind: "success" | "error" | "info", msg: string) => void;
}

/** Outcome of the live value comparison for a case with an expected value. */
interface ValueCheck {
  /** True when the live value equalled `expect_value`. */
  ok?: boolean;
  /** The live value found for `expect_key` (undefined when the key is absent). */
  actual?: string;
  /** Set when the value could not be read/compared (not an error state per se). */
  error?: string;
}

interface Row extends PolicyTestCase {
  /** Authoritative verdict from the last Run, if any. */
  verdict?: PolicyTestResultRow;
  /** Live value-assertion outcome from the last Run, if any. */
  valueCheck?: ValueCheck;
}

function emptyRow(): Row {
  return { path: "", capability: "read", expect: "allow" };
}

/**
 * The policies a case is evaluated against, as an editable comma list.
 *
 * `undefined` (the field never set) means "a normal token", which the
 * backend resolves to `["default"]` — so the input shows `default` as a
 * placeholder rather than pre-filling it, and a blank field keeps meaning
 * "whatever a real token carries". Typing a list replaces that set.
 */
function attachedText(policies: string[] | undefined): string {
  return policies === undefined ? "" : policies.join(", ");
}

function parseAttached(text: string): string[] | undefined {
  const names = text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return names.length ? names : undefined;
}

/**
 * Map a KV v2 policy path (`<mount>/data/<secret>`) to the (mount, path)
 * pair `read_secret` expects. The GUI's `read_secret` re-inserts the `data/`
 * infix via `adjust_kv_path`, so we hand it the mount (with the trailing
 * slash it strips) and the mount-prefixed logical path *without* the infix —
 * exactly what the Secrets page passes. Returns null for any other shape
 * (metadata paths, non-KV mounts), where a value assertion is meaningless.
 */
function policyPathToKvRead(policyPath: string): { mount: string; path: string } | null {
  const m = policyPath.match(/^([^/]+)\/data\/(.+)$/);
  if (!m) return null;
  const mount = m[1];
  return { mount: `${mount}/`, path: `${mount}/${m[2]}` };
}

/**
 * Validate & test panel for a draft policy. Top section lists client-side
 * lint/parse findings; the bottom section runs `(path, capability, expect)`
 * cases through the authoritative backend dry-run and shows the verdict and
 * matched rule. Saved cases double as a regression gate on every save.
 */
export function PolicyValidatorPanel({ name, hcl, savedCases, onSavedCasesChange, toast }: Props) {
  const [rows, setRows] = useState<Row[]>([]);
  const [running, setRunning] = useState(false);
  const [saving, setSaving] = useState(false);

  // Seed editable rows from the saved cases whenever they change.
  useEffect(() => {
    setRows(savedCases.length ? savedCases.map((c) => ({ ...c })) : [emptyRow()]);
  }, [savedCases]);

  // Client-side lint (non-authoritative; instant feedback).
  const parsed = parsePolicyHcl(hcl);
  const findings: LintFinding[] = parsed.ok ? lintPolicyModel(parsed.model) : [];
  const parseErrors = parsed.ok ? [] : parsed.errors;

  function update(i: number, patch: Partial<Row>) {
    setRows(rows.map((r, idx) => (idx === i ? { ...r, ...patch, verdict: undefined, valueCheck: undefined } : r)));
  }
  function addRow() {
    setRows([...rows, emptyRow()]);
  }
  function removeRow(i: number) {
    setRows(rows.filter((_, idx) => idx !== i));
  }

  async function runAll() {
    const cases = rows.filter((r) => r.path.trim());
    if (!cases.length) return;
    setRunning(true);
    try {
      const res = await api.policyTest(
        hcl,
        cases.map((c) => ({
          path: c.path,
          capability: c.capability,
          env: c.env?.trim() || undefined,
          policies: c.policies,
        })),
        name,
      );
      if (!res.parse_ok) {
        toast("error", `Policy does not parse: ${res.errors[0] ?? "syntax error"}`);
        return;
      }
      // Map verdicts back onto the rows by index of the filtered set.
      let k = 0;
      const verdicts = rows.map((r) => (r.path.trim() ? res.results[k++] : undefined));

      // For cases asserting a value, read the live secret and compare. Only
      // meaningful when the case expects `allow` and the policy did allow it.
      const valueChecks = await Promise.all(
        rows.map(async (r, i): Promise<ValueCheck | undefined> => {
          const v = verdicts[i];
          if (!v || !r.expect_value?.length) return undefined;
          if (r.expect !== "allow") return { error: "needs expect = allow" };
          if (!v.allowed) return { error: "denied — cannot read value" };
          const kv = policyPathToKvRead(r.path.trim());
          if (!kv) return { error: "not a kv-v2 data path" };
          const key = r.expect_key?.trim();
          if (!key) return { error: "no key specified" };
          try {
            const secret = await api.readSecret(kv.path, kv.mount, "kv-v2", r.env?.trim() || undefined);
            const raw = secret.data?.[key];
            const actual = raw == null ? undefined : String(raw);
            return { ok: actual === r.expect_value, actual };
          } catch (e: unknown) {
            return { error: extractError(e) };
          }
        }),
      );

      setRows(
        rows.map((r, i) => {
          if (!r.path.trim()) return { ...r, verdict: undefined, valueCheck: undefined };
          return { ...r, verdict: verdicts[i], valueCheck: valueChecks[i] };
        }),
      );
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setRunning(false);
    }
  }

  async function save() {
    setSaving(true);
    try {
      const cases: PolicyTestCase[] = rows
        .filter((r) => r.path.trim())
        .map((r) => ({
          path: r.path.trim(),
          capability: r.capability,
          expect: r.expect,
          note: r.note,
          env: r.env?.trim() || undefined,
          expect_key: r.expect_key?.trim() || undefined,
          expect_value: r.expect_value || undefined,
          policies: r.policies,
        }));
      await api.writePolicyTests(name, cases);
      onSavedCasesChange(cases);
      toast("success", `Saved ${cases.length} test case${cases.length === 1 ? "" : "s"}`);
    } catch (e: unknown) {
      toast("error", extractError(e));
    } finally {
      setSaving(false);
    }
  }

  // Pass/fail summary over rows that have been run.
  const run = rows.filter((r) => r.verdict);
  const passed = run.filter((r) => verdictPasses(r)).length;

  return (
    <div className="space-y-4">
      {/* Lint / parse results */}
      <Card title="Validation">
        {parseErrors.length > 0 ? (
          <div className="space-y-1">
            {parseErrors.map((e, i) => (
              <div key={i} className="flex items-start gap-2 text-sm">
                <Badge variant="error" label="error" />
                <span className="text-red-400">
                  {e.message}
                  {e.line ? ` (line ${e.line})` : ""}
                </span>
              </div>
            ))}
          </div>
        ) : findings.length === 0 ? (
          <p className="text-sm text-green-400">No lint findings — the policy looks well-formed.</p>
        ) : (
          <div className="space-y-1">
            {findings.map((f, i) => (
              <div key={i} className="flex items-start gap-2 text-sm">
                <Badge variant={f.severity === "error" ? "error" : "warning"} label={f.severity} />
                <span className={f.severity === "error" ? "text-red-400" : "text-yellow-400"}>
                  {f.message}
                  {f.path ? ` — ${f.path}` : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Effectivity test cases */}
      <Card
        title="Effectivity test cases"
        actions={
          <div className="flex items-center gap-2">
            {run.length > 0 && (
              <span className={`text-xs ${passed === run.length ? "text-green-400" : "text-red-400"}`}>
                {passed} / {run.length} pass
              </span>
            )}
            <Button size="sm" variant="secondary" onClick={runAll} disabled={running}>
              {running ? "Running…" : "Run"}
            </Button>
            <Button size="sm" onClick={save} disabled={saving}>
              {saving ? "Saving…" : "Save cases"}
            </Button>
          </div>
        }
      >
        <p className="mb-3 text-xs text-[var(--color-text-muted)]">
          Each case asserts the policy should <em>allow</em> or <em>deny</em> a capability on a path. Run evaluates them
          against the authoritative backend matcher and shows the rule that decided each verdict. An optional{" "}
          <strong>Environment</strong> is fed to the matcher as the <code>env</code> request parameter, so a rule that
          restricts environments (<code>required_parameters</code>/<code>allowed_parameters</code>) is actually
          exercised. Set an <strong>expected value</strong> to additionally read the live secret and check the value
          matches — this runs at <em>Run</em> time only and does not gate saves. Saved cases gate every future save on
          their allow/deny verdict.
        </p>
        <p className="mb-3 text-xs text-[var(--color-text-muted)]">
          <strong>With policies</strong> is the set a real token carries alongside this one — left blank it means{" "}
          <code>default</code>, which every token gets. It matters because ACL precedence picks a <em>single</em>{" "}
          winning rule instead of unioning across policies, so a narrow rule in <code>default</code>{" "}
          <em>replaces</em> a broad one here. When that happens the verdict is tagged{" "}
          <strong>narrowed</strong> and names the policy whose rule won. The fix is usually to restate that exact path
          in this policy — identical path strings do merge.
        </p>
        <div className="space-y-3">
          {rows.map((r, i) => (
            <div
              key={i}
              className="space-y-2 rounded-md border border-[var(--color-border)] p-2"
            >
              <div className="grid grid-cols-12 items-end gap-2">
                <div className="col-span-5 min-w-0">
                  <Input
                    label={i === 0 ? "Path" : undefined}
                    value={r.path}
                    onChange={(e) => update(i, { path: e.target.value })}
                    placeholder="secret/data/team/x"
                  />
                </div>
                <div className="col-span-2">
                  <Select
                    label={i === 0 ? "Capability" : undefined}
                    value={r.capability}
                    onChange={(e) => update(i, { capability: e.target.value })}
                    options={CAPABILITIES.map((c) => ({ value: c, label: c }))}
                  />
                </div>
                <div className="col-span-2 min-w-0">
                  <Input
                    label={i === 0 ? "Environment" : undefined}
                    value={r.env ?? ""}
                    onChange={(e) => update(i, { env: e.target.value })}
                    placeholder="base"
                  />
                </div>
                <div className="col-span-2">
                  <Select
                    label={i === 0 ? "Expect" : undefined}
                    value={r.expect}
                    onChange={(e) => update(i, { expect: e.target.value as "allow" | "deny" })}
                    options={[
                      { value: "allow", label: "allow" },
                      { value: "deny", label: "deny" },
                    ]}
                  />
                </div>
                <div className="col-span-1 flex justify-end">
                  <Button size="sm" variant="ghost" onClick={() => removeRow(i)} title="Remove case">
                    ✕
                  </Button>
                </div>
              </div>
              <div className="grid grid-cols-12 items-end gap-2">
                <div className="col-span-3 min-w-0">
                  <Input
                    label={i === 0 ? "Expect value: key" : undefined}
                    value={r.expect_key ?? ""}
                    onChange={(e) => update(i, { expect_key: e.target.value })}
                    placeholder="optional"
                  />
                </div>
                <div className="col-span-3 min-w-0">
                  <Input
                    label={i === 0 ? "= value" : undefined}
                    value={r.expect_value ?? ""}
                    onChange={(e) => update(i, { expect_value: e.target.value })}
                    placeholder="expected value"
                  />
                </div>
                <div className="col-span-2 min-w-0">
                  <Input
                    label={i === 0 ? "With policies" : undefined}
                    value={attachedText(r.policies)}
                    onChange={(e) => update(i, { policies: parseAttached(e.target.value) })}
                    placeholder="default"
                  />
                </div>
                <div className="col-span-4 min-w-0">
                  {r.verdict ? (
                    <VerdictCell row={r} policyName={name} />
                  ) : (
                    <Input
                      label={i === 0 ? "Note" : undefined}
                      value={r.note ?? ""}
                      onChange={(e) => update(i, { note: e.target.value })}
                      placeholder="optional"
                    />
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3">
          <Button size="sm" variant="ghost" onClick={addRow}>
            + Add case
          </Button>
        </div>
      </Card>

      <CollapsibleSection title="About the verdict">
        <p className="text-xs text-[var(--color-text-muted)]">
          The <strong>Run</strong> verdict is authoritative — it comes from the server building an in-memory ACL from
          your draft <em>plus</em> the policies each case names, and evaluating it with the production matcher. The
          visual builder&apos;s inline hints are a client-side preview only.
        </p>
        <p className="mt-2 text-xs text-[var(--color-text-muted)]">
          Capabilities are unioned only between rules whose path string is <em>identical</em>. Across different paths
          there is no union: exact beats prefix (<code>*</code>) beats segment-wildcard (<code>+</code>), and the one
          winning rule&apos;s capabilities are the whole answer. This is HashiCorp Vault&apos;s behaviour and is
          deliberate — operators rely on a narrow rule out-specifying a broad one in order to restrict. Remedies, in
          order of preference: restate the path here, drop <code>default</code> from the token
          (<code>token_no_default_policy</code>), or — almost always wrong, since it widens every tenant — widen the
          rule in <code>default</code>.
        </p>
      </CollapsibleSection>
    </div>
  );
}

function verdictPasses(r: Row): boolean {
  if (!r.verdict) return false;
  const expectedAllow = r.expect === "allow";
  if (r.verdict.allowed !== expectedAllow) return false;
  // A value assertion, when set, must also hold. An unresolvable check
  // (error) fails the case so it can't silently pass.
  if (r.expect_value?.length) return r.valueCheck?.ok === true;
  return true;
}

/** "prefix: rustion/targets/+ (via default)" — the rule that decided it. */
function matchSummary(v: PolicyTestResultRow): string {
  if (!v.matched_path) return "no rule matched";
  const via = v.granting_policies?.length ? ` (via ${v.granting_policies.join(", ")})` : "";
  return `${v.match_kind}: ${v.matched_path}${via}`;
}

function VerdictCell({ row, policyName }: { row: Row; policyName: string }) {
  const v = row.verdict!;
  const pass = verdictPasses(row);
  const vc = row.valueCheck;
  // The winning rule came from somewhere other than the policy being
  // edited, and the draft on its own would have allowed it: that is the
  // cross-policy narrowing, and `granting_policies` names the cause.
  const others = (v.granting_policies ?? []).filter((p) => p !== policyName);
  const narrowed = v.draft_only_allowed && !v.allowed && others.length > 0;
  return (
    <div className="flex flex-col gap-0.5 text-xs">
      <div className="flex items-center gap-1.5">
        <Badge variant={pass ? "success" : "error"} label={pass ? "pass" : "fail"} />
        <span className={v.allowed ? "text-green-400" : "text-red-400"}>{v.allowed ? "allowed" : "denied"}</span>
        {narrowed ? <Badge variant="warning" label="narrowed" /> : null}
        {row.env?.trim() ? (
          <span className="text-[var(--color-text-muted)]">env={row.env.trim()}</span>
        ) : null}
      </div>
      <span className="truncate text-[var(--color-text-muted)]" title={matchSummary(v)}>
        {matchSummary(v)}
      </span>
      {narrowed ? (
        <span className="text-yellow-400">
          {others.join(", ")} wins here — restate <code>{v.matched_path}</code> in this policy to keep the grant
        </span>
      ) : null}
      {v.missing_policies?.length ? (
        <span className="text-yellow-400">no such policy: {v.missing_policies.join(", ")}</span>
      ) : null}
      {vc ? (
        <span className={vc.error ? "text-yellow-400" : vc.ok ? "text-green-400" : "text-red-400"}>
          {vc.error
            ? `value: ${vc.error}`
            : vc.ok
              ? "value matches"
              : `value mismatch (got ${vc.actual ?? "∅"})`}
        </span>
      ) : null}
    </div>
  );
}
