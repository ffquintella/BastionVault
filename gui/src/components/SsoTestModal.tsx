// SSO test sign-in (Settings → SSO providers → Test): runs the provider's saved
// config end to end and shows what came back. Does not sign the GUI in; the
// test token is revoked by `oidc_test_complete`.
import { useEffect, useRef, useState } from "react";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import { Badge, Button, Modal } from "./ui";
import * as api from "../lib/api";
import type { SsoTestReport, SsoTestStatus, SsoTestStep } from "../lib/api";
import { extractError } from "../lib/error";

const TEST_TIMEOUT_SECS = 120;

type Phase = "idle" | "starting" | "waiting" | "done";

const STATUS_BADGE: Record<SsoTestStatus, { label: string; variant: "success" | "warning" | "error" | "info" }> = {
  ok: { label: "OK", variant: "success" },
  warn: { label: "Check", variant: "warning" },
  fail: { label: "Failed", variant: "error" },
  info: { label: "Note", variant: "info" },
};

export function SsoTestModal({
  mount,
  displayName,
  onClose,
}: {
  mount: string;
  displayName: string;
  onClose: () => void;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [report, setReport] = useState<SsoTestReport | null>(null);
  const alive = useRef(true);
  useEffect(
    () => () => {
      alive.current = false;
    },
    [],
  );

  async function runTest() {
    setReport(null);
    setPhase("starting");
    let sessionId: string | null = null;
    try {
      const start = await api.oidcLoginStart({ mount });
      sessionId = start.sessionId;
      if (!alive.current) {
        await api.oidcLoginCancel(sessionId).catch(() => undefined);
        return;
      }
      setPhase("waiting");
      await shellOpen(start.authUrl);
      const result = await api.oidcTestComplete({ sessionId, timeoutSecs: TEST_TIMEOUT_SECS });
      if (!alive.current) return;
      setReport({
        ...result,
        steps: [
          {
            name: "Discovery and authorization URL",
            status: "ok",
            detail: "The vault reached the provider and built the sign-in URL.",
          },
          ...result.steps,
        ],
      });
    } catch (err: unknown) {
      if (sessionId) await api.oidcLoginCancel(sessionId).catch(() => undefined);
      if (!alive.current) return;
      // The flow could not start (provider unreachable, untrusted certificate,
      // redirect URI not allowed, callback port busy) or the browser would not open.
      setReport({
        ok: false,
        steps: [
          {
            name: sessionId ? "Opening the browser" : "Discovery and authorization URL",
            status: "fail",
            detail: extractError(err),
          },
        ],
        display_name: "",
        role: "",
        subject: "",
        groups: [],
        policies: [],
        ttl_secs: null,
        metadata: {},
        token_revoked: false,
      });
    } finally {
      if (alive.current) setPhase("done");
    }
  }

  const busy = phase === "starting" || phase === "waiting";

  return (
    <Modal
      open
      onClose={onClose}
      title={`Test SSO sign-in: ${displayName || mount}`}
      size="lg"
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button onClick={runTest} loading={busy} disabled={busy}>
            {phase === "done" ? "Run again" : "Start test"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {phase === "idle" && (
          <p className="text-sm text-[var(--color-text-muted)]">
            Signs in through this provider's saved configuration using your
            system browser, then shows what the provider sent and whether the
            login would be accepted. You are not signed in by this test, and
            the token it creates is revoked immediately.
          </p>
        )}

        {phase === "starting" && (
          <p className="text-sm text-[var(--color-text-muted)]" role="status">
            Contacting the provider…
          </p>
        )}

        {phase === "waiting" && (
          <div className="space-y-1" role="status">
            <p className="text-sm text-[var(--color-text)]">Waiting for you to sign in in your browser…</p>
            <p className="text-xs text-[var(--color-text-muted)]">
              The test gives up after {TEST_TIMEOUT_SECS / 60} minutes. If you close this window first, the
              callback port stays busy until then.
            </p>
          </div>
        )}

        {report && <Report report={report} />}
      </div>
    </Modal>
  );
}

function Report({ report }: { report: SsoTestReport }) {
  return (
    <div className="space-y-4">
      <div
        role="status"
        className={`rounded-lg border px-3 py-2 text-sm font-medium ${
          report.ok
            ? "border-green-500/30 bg-green-500/10 text-green-400"
            : "border-red-500/30 bg-red-500/10 text-red-400"
        }`}
      >
        {report.ok
          ? "This sign-in would work: the provider verified the user and the role accepted it."
          : "This sign-in would not work. See the failing step below."}
      </div>

      <ul className="space-y-2">
        {report.steps.map((s) => (
          <StepRow key={s.name} step={s} />
        ))}
      </ul>

      {report.ok && (
        <section className="space-y-2">
          <h4 className="text-sm font-semibold text-[var(--color-text)]">Received from the provider</h4>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <Field label="User" value={report.display_name} />
            <Field label="Subject (sub)" value={report.subject} mono />
            <Field label="Role" value={report.role} />
            <Field label="Groups" value={report.groups.join(", ")} />
            <Field label="Vault policies" value={report.policies.join(", ")} />
            <Field label="Token TTL" value={report.ttl_secs === null ? "" : `${report.ttl_secs} s`} />
            {Object.entries(report.metadata)
              .filter(([k]) => k !== "groups")
              .map(([k, v]) => (
                <Field key={k} label={k} value={v} mono />
              ))}
          </dl>
        </section>
      )}
    </div>
  );
}

function StepRow({ step }: { step: SsoTestStep }) {
  const badge = STATUS_BADGE[step.status];
  return (
    <li className="flex items-start gap-3">
      <div className="shrink-0 pt-0.5">
        <Badge label={badge.label} variant={badge.variant} />
      </div>
      <div className="min-w-0">
        <div className="text-sm text-[var(--color-text)]">{step.name}</div>
        <div className="text-xs text-[var(--color-text-muted)] break-words">{step.detail}</div>
      </div>
    </li>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt className="text-[var(--color-text-muted)]">{label}</dt>
      <dd className={`min-w-0 break-words ${mono ? "font-mono text-xs" : ""} text-[var(--color-text)]`}>
        {value || <span className="text-[var(--color-text-muted)]">not provided</span>}
      </dd>
    </>
  );
}
