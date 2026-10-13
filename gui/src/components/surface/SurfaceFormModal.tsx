import { useEffect, useState } from "react";
import * as api from "../../lib/api";
import { extractError } from "../../lib/error";
import { Button, Modal } from "../ui";
import { SurfaceForm, prefillValues } from "./SurfaceForm";

/**
 * What opened the modal: a table's toolbar action (create, with a "choose
 * the kind" step when it lists several forms) or a row action with
 * `open_form` (edit: the row's record is read and prefills the form).
 */
export type SurfaceModalRequest =
  | { kind: "create"; action: api.SurfaceTableAction }
  | { kind: "edit"; action: api.SurfaceRowAction; row: Record<string, unknown> };

/** The row's string fields: `{field}` substitutions for its bindings. */
export function rowParams(row: Record<string, unknown>): Record<string, string> {
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(row)) {
    if (typeof v === "string") params[k] = v;
  }
  return params;
}

/**
 * The form a row action opens for `row`, or an error naming why none
 * applies. A row whose `select_by` value has no form is an error, never a
 * fallback to some other form.
 */
export function formIdForRow(
  open: api.SurfaceOpenForm,
  row: Record<string, unknown>,
): { id: string } | { error: string } {
  if (open.select_by) {
    const value = row[open.select_by];
    const id = typeof value === "string" ? open.forms_by_value?.[value] : undefined;
    return id
      ? { id }
      : { error: `No form for ${open.select_by} "${typeof value === "string" ? value : ""}".` };
  }
  return open.form ? { id: open.form } : { error: "This action names no form." };
}

type Step =
  | { step: "choose" }
  | { step: "loading" }
  | { step: "form"; form: api.SurfaceForm; initial?: Record<string, unknown>; fromChooser: boolean }
  | { step: "saved"; warnings: string[] }
  | { step: "error"; message: string };

function formTitle(form: api.SurfaceForm): string {
  return form.title || form.id;
}

/**
 * Modal host for schema-v2 forms (`presentation: "modal"`). Owns the
 * kind chooser, the prefill read for an edit, the form itself and, when a
 * save came back with warnings, a summary of them. `onSaved` fires on
 * every successful submit (the page re-lists its tables); the modal closes
 * itself unless there are warnings to read first.
 */
export function SurfaceFormModal({
  request,
  forms,
  entry,
  onClose,
  onSaved,
}: {
  request: SurfaceModalRequest;
  /** The page's modal forms, by id. */
  forms: Record<string, api.SurfaceForm>;
  entry: api.ActiveSurfaceEntry;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [state, setState] = useState<Step>(() => initialStep(request, forms));

  // Edit: read the record the row points at, then show the form prefilled
  // from it. Secret fields are never prefilled (see `prefillValues`).
  useEffect(() => {
    if (request.kind !== "edit") return;
    const open = request.action.open_form;
    if (!open) return;
    const picked = formIdForRow(open, request.row);
    if ("error" in picked) return;
    const form = forms[picked.id];
    if (!form) return;
    let cancelled = false;
    api
      .pluginSurfaceDispatch(
        request.action.binding.op,
        request.action.binding.path,
        entry.mount,
        rowParams(request.row),
      )
      .then((data) => {
        if (cancelled) return;
        setState({ step: "form", form, initial: prefillValues(form.schema, data), fromChooser: false });
      })
      .catch((e) => {
        if (cancelled) return;
        setState({ step: "error", message: extractError(e) });
      });
    return () => {
      cancelled = true;
    };
    // Once per request. A bundle refresh (the page re-lists after a save,
    // or the surface watcher fires) hands in new `forms` objects; re-running
    // then would re-read the record and throw away what the user typed or
    // the warnings they are reading.
  }, [request]); // eslint-disable-line react-hooks/exhaustive-deps

  const title =
    state.step === "form" ? formTitle(state.form) : request.action.label;

  function handleSubmitted(_resp: Record<string, unknown> | null, warnings: string[]) {
    onSaved();
    if (warnings.length > 0) setState({ step: "saved", warnings });
    else onClose();
  }

  return (
    <Modal open onClose={onClose} title={title} size="lg">
      {state.step === "choose" && request.kind === "create" && (
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            {request.action.prompt || "Choose what to add."}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {request.action.forms.map((id) => {
              const form = forms[id];
              if (!form) return null;
              return (
                <Button
                  key={id}
                  variant="secondary"
                  className="min-w-0 justify-start"
                  onClick={() => setState({ step: "form", form, fromChooser: true })}
                >
                  <span className="truncate">{formTitle(form)}</span>
                </Button>
              );
            })}
          </div>
        </div>
      )}
      {state.step === "loading" && (
        <div className="text-sm text-[var(--color-text-muted)]">Loading…</div>
      )}
      {state.step === "error" && (
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-danger)]">{state.message}</p>
          <div className="flex justify-end">
            <Button variant="ghost" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      )}
      {state.step === "form" && (
        <div className="space-y-3">
          {state.fromChooser && (
            <Button variant="ghost" size="sm" onClick={() => setState({ step: "choose" })}>
              ← Choose another kind
            </Button>
          )}
          <SurfaceForm
            // Remount per form so one form's values never leak into another.
            key={state.form.id}
            spec={state.form}
            entry={entry}
            mode={request.kind === "edit" ? "edit" : "create"}
            initialValues={state.initial}
            pathParams={request.kind === "edit" ? rowParams(request.row) : undefined}
            onSubmitted={handleSubmitted}
            onCancel={onClose}
            hideTitle
            layout="grid"
          />
        </div>
      )}
      {state.step === "saved" && (
        <div className="space-y-3">
          <p className="text-sm">Saved, with warnings:</p>
          <ul className="list-disc pl-5 space-y-1 text-sm text-[var(--color-warning)]">
            {state.warnings.map((w, i) => (
              <li key={i} className="break-words">
                {w}
              </li>
            ))}
          </ul>
          <div className="flex justify-end">
            <Button onClick={onClose}>Close</Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function initialStep(
  request: SurfaceModalRequest,
  forms: Record<string, api.SurfaceForm>,
): Step {
  if (request.kind === "create") {
    const available = request.action.forms.filter((id) => forms[id]);
    if (available.length === 0) {
      return { step: "error", message: "This action's form is not on this page." };
    }
    if (available.length === 1) {
      return { step: "form", form: forms[available[0]], fromChooser: false };
    }
    return { step: "choose" };
  }
  const open = request.action.open_form;
  if (!open) return { step: "error", message: "This action opens no form." };
  const picked = formIdForRow(open, request.row);
  if ("error" in picked) return { step: "error", message: picked.error };
  if (!forms[picked.id]) {
    return { step: "error", message: `Form "${picked.id}" is not on this page.` };
  }
  return { step: "loading" };
}
