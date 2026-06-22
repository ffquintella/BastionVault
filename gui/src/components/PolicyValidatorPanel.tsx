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

interface Row extends PolicyTestCase {
  /** Authoritative verdict from the last Run, if any. */
  verdict?: PolicyTestResultRow;
}

function emptyRow(): Row {
  return { path: "", capability: "read", expect: "allow" };
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
    setRows(rows.map((r, idx) => (idx === i ? { ...r, ...patch, verdict: undefined } : r)));
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
        cases.map((c) => ({ path: c.path, capability: c.capability })),
      );
      if (!res.parse_ok) {
        toast("error", `Policy does not parse: ${res.errors[0] ?? "syntax error"}`);
        return;
      }
      // Map verdicts back onto the rows by index of the filtered set.
      let k = 0;
      setRows(
        rows.map((r) => {
          if (!r.path.trim()) return { ...r, verdict: undefined };
          return { ...r, verdict: res.results[k++] };
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
        .map((r) => ({ path: r.path.trim(), capability: r.capability, expect: r.expect, note: r.note }));
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
          against the authoritative backend matcher and shows the rule that decided each verdict. Saved cases gate every
          future save.
        </p>
        <div className="space-y-2">
          {rows.map((r, i) => (
            <div key={i} className="grid grid-cols-12 items-end gap-2">
              <div className="col-span-4 min-w-0">
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
              <div className="col-span-3 min-w-0">
                {r.verdict ? (
                  <VerdictCell row={r} />
                ) : (
                  <Input
                    label={i === 0 ? "Note" : undefined}
                    value={r.note ?? ""}
                    onChange={(e) => update(i, { note: e.target.value })}
                    placeholder="optional"
                  />
                )}
              </div>
              <div className="col-span-1">
                <Button size="sm" variant="ghost" onClick={() => removeRow(i)} title="Remove">
                  ✕
                </Button>
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
          your draft and evaluating it with the production matcher. The visual builder&apos;s inline hints are a
          client-side preview only.
        </p>
      </CollapsibleSection>
    </div>
  );
}

function verdictPasses(r: Row): boolean {
  if (!r.verdict) return false;
  const expectedAllow = r.expect === "allow";
  return r.verdict.allowed === expectedAllow;
}

function VerdictCell({ row }: { row: Row }) {
  const v = row.verdict!;
  const pass = verdictPasses(row);
  return (
    <div className="flex flex-col gap-0.5 text-xs">
      <div className="flex items-center gap-1.5">
        <Badge variant={pass ? "success" : "error"} label={pass ? "pass" : "fail"} />
        <span className={v.allowed ? "text-green-400" : "text-red-400"}>{v.allowed ? "allowed" : "denied"}</span>
      </div>
      <span className="truncate text-[var(--color-text-muted)]" title={v.matched_path ?? "no rule matched"}>
        {v.matched_path ? `${v.match_kind}: ${v.matched_path}` : "no rule matched"}
      </span>
    </div>
  );
}
