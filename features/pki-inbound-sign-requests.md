# Feature: PKI Inbound Sign Requests (external CSR import + decide)

## Summary

Give the PKI engine an **inbound** CSR flow: import a PKCS#10 CSR that was
generated somewhere else, park it as a durable *sign request*, inspect exactly
what it asks for, dry-run it against every role on the mount, then either
**approve** it (sign, with a chosen mode and optional overrides) or **reject**
it with a recorded reason.

This is the mirror image of the existing outgoing flow. `pki/csr/*`
([features/pki-key-management-and-lifecycle.md](pki-key-management-and-lifecycle.md))
is *we generate a CSR, an upstream CA signs it*. This feature is *someone else
generated a CSR, we are the CA and have to decide*.

## Motivation

- **The engine can already sign a foreign CSR, but nothing helps you decide.**
  `pki/sign/:role` and `pki/sign-verbatim` have existed since Phase 5; the
  GUI never exposed them, and even the API forces an all-or-nothing call: you
  post a PEM and either get a certificate or an error code. There is no way to
  ask "what would this produce, and would any role accept it?" before minting.
- **"Not signing" is a decision that has to be recorded.** A CSR that arrives
  by email from a third party is often *refused* — wrong DN, wrong key size,
  no ticket, unclear requester. Today refusal happens in the operator's inbox
  and leaves no trace in the vault. An auditor asking "who asked for a cert
  under this domain and why did we say no?" has nowhere to look.
- **A CSR is not self-describing to a human.** Base64 hides the subject, the
  SANs, the key algorithm and size, and whether the self-signature even
  verifies. Operators paste blind, then read a `ErrPkiDataInvalid` and guess
  which of `allowed_domains` / `allow_ip_sans` / `allow_any_name` bit them.
- **Signing decisions are exactly the kind of action that wants a queue.**
  Import and approval can be separated in time and (by policy) in operator,
  which is what a two-person rule on a CA needs as a substrate.

## Scope

### In scope

1. **Durable sign-request records** (`pki/sign-request/*`)
   - `WRITE  pki/sign-request/import` — accept a PEM/DER CSR, verify its
     self-signature, extract subject / SANs / key algorithm / SPKI
     fingerprint, persist as `status = pending`, return the id + summary.
   - `LIST   pki/sign-request` — pending and decided ids.
   - `READ   pki/sign-request/<id>` — full record incl. the CSR PEM, the
     parsed summary, and the decision (serial + issuer, or reject reason).
   - `DELETE pki/sign-request/<id>` — drop a record.
   - Persisted format is versioned (`version: 1`) with `#[serde(default)]` on
     every field added after the fact, per the read-old/write-new rule.
2. **Dry run** (`WRITE pki/sign-request/<id>/preflight`)
   - Runs the *same* decision code the signing path runs — role lookup, CN
     and DNS-SAN policy, IP-SAN gate, key-reuse pin, issuer resolution,
     `issuing_certificates` usage bit, TTL clamp to the issuer's remaining
     lifetime, PQC/classical class match — and reports the verdict instead of
     minting.
   - With no `role`, evaluates **every** role on the mount plus verbatim, so
     the operator sees which roles would accept the request and why the others
     would not.
   - Emits non-blocking `warnings` for things that are legal but suspicious:
     the CSR's key algorithm differing from the role's `key_type`/`key_bits`,
     a TTL clamped by the issuer, SANs dropped because the role sets
     `use_csr_sans = false`.
3. **Approve** — two paths, not one flag
   - `WRITE pki/sign-request/<id>/approve` signs under a named `role`;
     role policy applies. Optional overrides: `common_name`, `alt_names`,
     `ttl`, `issuer_ref`, `key_ref`, `upn_sans`, `ad_sid` — the same knobs
     `pki/sign/:role` takes.
   - `WRITE pki/sign-request/<id>/approve-verbatim` takes the subject and
     SANs exactly as the CSR states them, **bypassing role policy**. It
     accepts only `ttl` and `issuer_ref`.
   - They are separate paths so a policy granting role-approval does not
     thereby grant a policy-free signature — the same split
     `pki/sign/:role` and `pki/sign-verbatim` have always had. The GUI
     presents them as one "mode" selector and routes accordingly.
   - Either records the outcome on the request (`status = signed`, serial,
     issuer, mode, role) and returns the cert, issuing CA and chain.
4. **Reject** (`WRITE pki/sign-request/<id>/reject`)
   - `reason` is **required** — a rejection with no reason is not a record.
   - Terminal: a rejected request cannot be approved afterwards. The record
     is kept for the audit trail; `DELETE` is the only way to remove it.
5. **Shared sign plan** (`crates/bv-engine-pki/src/sign_flow.rs`)
   - The decide-then-build split extracted from `path_issue.rs` so that
     `pki/sign/:role`, `pki/sign-verbatim`, the preflight and the approve path
     all run one implementation. A dry run that can drift from the real path
     is worse than no dry run.
6. **GUI** — a *Sign Requests* tab on the PKI page: import (paste or file),
   a request list with status, a detail panel showing the decoded CSR, the
   per-role preflight verdicts, the mode/override form, and Approve / Reject.
7. **Tauri commands** — `pki_sign_request_{import,list,read,preflight,approve,
   reject,delete}`, mirroring the engine surface.

### Out of scope (explicit)

- **Two-person rule / separation of duties.** The queue is the substrate for
  it (import and approve are distinct operations on distinct paths, so policy
  can grant them to different identities), but no enforcement that approver ≠
  importer is implemented here.
- **Notifications.** No mail/webhook when a request lands. The
  `notifications` engine can be wired to it later.
- **Reopening a rejection.** Terminal by design; delete and re-import.
- **ACME.** ACME orders have their own authorisation model and do not pass
  through this queue.
- **Bulk approve.** One decision, one request.

## Known limits

- **The list endpoint returns ids only**, so the GUI reads every record to
  render the table — the same N+1 the outgoing `pki/csr/*` tab has. Undecided
  requests are capped per mount (`MAX_PENDING_REQUESTS = 500`), but *decided*
  records accumulate until an operator deletes them, and they are read too. A
  mount that keeps years of decisions will want a summary-bearing list
  response or server-side paging.
- **Preflight with no `role` loads the issuer once per role.** Fine for the
  handful of roles a mount usually carries; it is a linear scan, not a
  constant-time one.
- **No pagination or search** on the queue. The GUI filters by status
  client-side.
- **The `MAX_PENDING_REQUESTS` cap has no automated test.** Exercising it
  needs 500 imports, and the duplicate scan is linear per import, so the
  test would do ~125k storage reads — minutes of suite time for one
  constant. The duplicate refusal it shares a code path with *is* tested
  (`test_sign_request_import_records_the_parsed_csr`).

## Security notes

- Verbatim approval **bypasses role policy** — no `allowed_domains`, no
  `allow_ip_sans` gate. That is why it lives on its own path
  (`sign-request/<id>/approve-verbatim`) rather than being a `mode` flag on
  `approve`: a policy can grant `pki/sign-request/+/approve` — sign what a
  role permits — without thereby granting a policy-free signature. It is
  surfaced in the GUI with an explicit warning and recorded on the request
  as `sign_mode = verbatim`. It also refuses `key_ref` / `upn_sans` /
  `ad_sid`: those are role-authorised knobs, and there is no role.
- Import verifies the CSR self-signature before storing anything. A CSR whose
  signature does not verify is rejected outright rather than parked — parking
  it would invite an operator to approve material whose holder is unproven.
- A CSR is not secret, but it is attacker-controlled input. Every string that
  reaches the GUI (subject DN, SANs, requester, notes) is rendered as text,
  never as markup, and the record caps the notes/requester fields.
- Import refuses a CSR whose SPKI fingerprint matches an already-pending
  request unless `allow_duplicate = true`, so a resend cannot quietly create a
  second approvable copy of the same ask.
- No new private key material: the engine never holds a key for an inbound
  CSR. The only key it touches is the issuer's, at approve time.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | `sign_flow.rs` extraction — shared plan/execute behind `sign/:role` + `sign-verbatim`, no behaviour change | Done |
| 2 | `pki/sign-request/*` paths, versioned record, import/list/read/delete | Done |
| 3 | Preflight dry run, all-roles evaluation, warnings | Done |
| 4 | Approve (role path + separate verbatim path, overrides) + reject with reason | Done |
| 5 | Tauri commands + GUI *Sign Requests* tab | Done |
| 6 | Two-person rule, notification hook | Todo |

## Current State

Phases 1–5 are implemented. The engine surface is reachable on both `v1` and
`v2` (logical paths are version-agnostic; documented under `v2` in
[docs/api.md](../docs/api.md)). Phase 6 is not started.
