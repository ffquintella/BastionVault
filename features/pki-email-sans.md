# Feature: PKI `rfc822Name` SANs (S/MIME-capable person certificates)

## Summary

Let a PKI role issue certificates that carry the subject's email address as
an `rfc822Name` entry in `subjectAlternativeName` — the identifier every
S/MIME client, every signed-email verifier and RFC 8550 §3 itself require in
order to bind a certificate to a mailbox.

The engine has never been able to emit one. `pki/issue/:role`,
`pki/sign/:role`, `pki/sign-verbatim` and `pki/csr/generate` accept DNS SANs,
IP SANs and (since the AD smart-card profile) UPN `otherName` SANs. There is
no email channel at all, and an `rfc822Name` present in a **caller-supplied
CSR is silently discarded** on its way through
[`csr::extract_san_request`](../crates/bv-engine-pki/src/csr.rs) — which is
both the bug that motivates this feature and, on its own, a violation of the
"no silent downgrade on a security-critical path" rule in
[AGENTS.md](../AGENTS.md) §7.

This feature adds:

- two role knobs — `allow_email_sans` (closed by default) and
  `allowed_email_domains` (an allow-list of mail domains),
- an `email_sans` request field on `pki/issue/:role`, `pki/sign/:role`,
  `pki/csr/generate` and the inbound sign-request `preflight` / `approve`
  bodies,
- `rfc822Name` emission in all four certificate builders (classical rcgen,
  ML-DSA, composite, and the generated-CSR path),
- `rfc822Name` **preservation** where a CSR already requests one, replacing
  the silent drop with either emission (role permits) or an explicit refusal
  (role does not).

## Motivation

- **S/MIME is unreachable today.** A role like `person-sign` with the
  EmailProtection EKU produces a certificate Outlook, Thunderbird and Apple
  Mail will all refuse to use for signing, because none of them will match a
  mailbox against a CN or a dNSName. RFC 8550 §3 is explicit: the email
  address belongs in `subjectAltName` as an `rfc822Name`. Without it the
  entire person-certificate use case — the reason a `person-sign` role
  exists — does not work.
- **The workaround produces a malformed certificate.** Putting
  `user@fgv.br` into `alt_names` today does not fail. It flows through
  [`split_alt_names`](../crates/bv-engine-pki/src/x509.rs), fails the
  `IpAddr` parse, and is emitted as a **`dNSName` containing an `@`** — a
  name no verifier will match and several will reject outright. An operator
  gets a plausible-looking certificate that is wrong in a way only a DER
  dump reveals.
- **Silent SAN loss is a defect on its own.** A requester who puts an
  `rfc822Name` in their CSR and gets back a certificate without one has no
  signal that anything happened. Every other unsatisfiable SAN request in
  this engine fails loudly (`allow_ip_sans`, `allow_upn_sans`,
  `allowed_domains`); this one does not, including on `sign-verbatim`, whose
  entire contract is "as stated in the CSR".
- **The plumbing already exists.** The AD smart-card work (Phase 5.7) built
  the pattern: a closed-by-default role knob, an allow-list, per-request
  validation that refuses rather than drops, and one encoder shared by the
  rcgen and hand-rolled-DER paths. This feature is the same shape, over a
  `GeneralName` variant that is core RFC 5280 rather than a Microsoft
  extension — strictly simpler than what shipped in 5.7.

## Scope

### Role surface (`pki/roles/:name`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `allow_email_sans` | bool | `false` | Permit `rfc822Name` SANs on issue / sign / csr-generate for this role. Closed by default. |
| `allowed_email_domains` | comma-string-slice | `[]` | Allow-list of mail domains (the part after `@`), matched case-insensitively, **exact — subdomains are not implied**. Empty + `allow_email_sans = true` means "any domain", matching the `allowed_upn_domains` / `allowed_key_refs` convention already in the role schema. |

Both are `#[serde(default)]`, so every role already in storage deserialises
unchanged and keeps producing a byte-identical certificate profile.

### Request surface

| Path | Field | Notes |
|---|---|---|
| `pki/issue/:role` | `email_sans` | Comma-separated addresses. |
| `pki/sign/:role` | `email_sans` | Consulted only when the role sets `use_csr_sans = false`; when `use_csr_sans = true` the addresses come from the CSR. |
| `pki/csr/generate` | `email_sans` | Requested in the generated CSR, for an upstream CA to honour or ignore. |
| `pki/sign-request/:id/preflight` | `email_sans` | Same semantics as `sign/:role`; reported in the dry run. |
| `pki/sign-request/:id/approve` | `email_sans` | Same. |
| `pki/sign-verbatim` | — | **Not declared.** There is no role to authorise an address against, exactly as with `upn_sans` / `ad_sid`, so the path accepts no `email_sans` field and one in the body reaches nothing. `sign_flow` refuses it outright on the one verbatim route that does carry a request body (`sign-request/:id/approve-verbatim`). `rfc822Name`s already inside the CSR *are* carried through, because carrying the CSR verbatim is the path's contract. |

### Certificate builders

| Builder | File | Change |
|---|---|---|
| Classical (rcgen) | `x509.rs` `params_for_subject` | push `SanType::Rfc822Name(Ia5String)` alongside the DNS / IP / UPN entries |
| ML-DSA | `x509_pqc.rs` `build_subject_alt_name` | push `GeneralName::Rfc822Name(Ia5String)` into the same `GeneralNames` |
| Composite | `x509_composite.rs` | free — it already delegates to `x509_pqc::build_subject_alt_name` |
| Generated CSR | `x509.rs` `build_leaf_csr` | free — it already routes through `params_for_subject` |

One SAN extension, as always: the email names ride in the same
`subjectAltName` as the DNS, IP and UPN entries. A second SAN extension
would make the certificate invalid.

### Not in scope

- **Internationalised addresses (SMTPUTF8 / EAI).** `rfc822Name` is an
  `IA5String`; a non-ASCII local part or a U-label domain has no legal
  encoding there. Rejected at validation time with a message that says so,
  rather than mangled. An operator with an IDN domain supplies the A-label.
- **`emailAddress` in the subject DN** (OID 1.2.840.113549.1.9.1). Deprecated
  by RFC 5280 §4.1.2.6 in favour of the SAN; adding it would invite the
  confusion this feature exists to remove.
- **Automatic EKU inference.** Setting `email_sans` does not add the
  EmailProtection EKU. EKU stays where it is, under the role's
  `ext_key_usage` — one knob, one meaning.
- **Name constraints.** Constraining an *issuer* to a mail domain
  (`nameConstraints` with an `rfc822Name` subtree) is a CA-certificate
  feature, separate from per-leaf policy, and stays out of this change.

## Security notes

- **Closed by default, and it must stay that way.** A CA that an
  organisation trusts for EmailProtection, issuing an unconstrained
  `rfc822Name`, lets anyone holding issue rights on the mount mint a signing
  certificate for *anyone's* mailbox — including the CEO's. That is the
  whole threat model of this feature in one sentence. `allow_email_sans`
  defaults to `false`; `allowed_email_domains` is the narrowing control an
  operator is expected to reach for immediately after enabling it.
- **Refuse, never drop.** Every path either emits the requested
  `rfc822Name` or returns an error naming `allow_email_sans` /
  `allowed_email_domains`. No path silently omits a requested address. This
  is the behaviour change that closes the existing defect.
- **Exact domain match, no subdomain implication.** `fgv.br` on the
  allow-list does not permit `evil.fgv.br`, mirroring
  `allowed_upn_domains`. Mail routing does not treat a subdomain as the
  parent domain, and neither should the allow-list.
- **Bounded input.** Addresses are capped at 254 characters (RFC 5321
  §4.5.3.1's maximum forward path) and must contain exactly one `@`, no
  whitespace, no control characters, and only ASCII. The cap keeps a
  hostile `email_sans` from bloating every certificate the role issues.
- **De-duplicated.** Repeated addresses in one request collapse to one SAN
  entry, so a caller cannot inflate a certificate by repetition.

### Behaviour change, called out for review

A CSR that carries an `rfc822Name` is currently **accepted and the address
silently dropped**. After this change, a role with `use_csr_sans = true`
(the default) and `allow_email_sans = false` **refuses** that CSR with a
message naming the knob.

This is intended, and it is the same shape as the existing `allow_ip_sans`
gate — an IP SAN in a CSR against a role with `allow_ip_sans = false`
already refuses rather than dropping. Operators who were unknowingly
submitting CSRs with email SANs to a strict role will see a new 400 where
they previously got a certificate. The certificate they were getting was not
the one they asked for, so surfacing that is the point. Recorded in
`CHANGELOG.md` under both **Changed** and **Security**.

## Defect found while implementing this

`pki/csr/generate` **failed on every call**, for every role and every
input, with `PKI: rcgen rejected key/cert: Certificate parameter
unsupported in CSR`. The GUI's *Outgoing CSR* tab was therefore entirely
non-functional, and nothing in the test suite covered the path.

Cause: [`build_leaf_csr`](../crates/bv-engine-pki/src/x509.rs) reuses
`params_for_subject` — the right call, since a CSR should request the same
SANs, key usages and EKUs the role would otherwise issue — and that
function sets `params.serial_number`. Its comment assumed
`serialize_request` would ignore the serial along with the validity dates.
rcgen 0.14 ignores the dates but **rejects the call outright** if a serial,
name constraints, CRL distribution points, or the AKI flag are set. The
builder now clears the serial before serialising.

Fixed here rather than filed separately because email SANs in an outgoing
CSR are unreachable without it, and the fix is two lines.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | `email_san.rs`: validation + `rfc822Name` encoder + unit tests | Done |
| 2 | Role knobs (`allow_email_sans`, `allowed_email_domains`) | Done |
| 3 | Emission in all four builders (classical / ML-DSA / composite / CSR) | Done |
| 4 | Request wiring: `issue`, `sign`, `csr/generate`, sign-request `preflight` / `approve`; CSR `rfc822Name` preservation incl. verbatim | Done |
| 5 | GUI: role form knobs + `email_sans` on the Issue and Outgoing-CSR tabs | Done |
| 6 | Integration test `tests/test_pki_email_sans.rs` — DER-level assertions across classical + PQC + CSR paths | Done |

## Current State

**Phases 1–6 — Done.** `rfc822Name` SANs are emitted by every certificate
path the engine has, gated on the role, and no longer silently dropped from
a caller's CSR.

Files:

- [`email_san.rs`](../crates/bv-engine-pki/src/email_san.rs) — the whole
  policy and encoding surface: `validate_email`, `resolve_email_sans`
  (comma-split + validate + de-dup), `rfc822_general_name` for the
  hand-rolled DER paths, and `rcgen_rfc822_san` for the classical one. One
  module so the two encoders cannot drift, mirroring `ad_ext.rs`.
- [`path_roles.rs`](../crates/bv-engine-pki/src/path_roles.rs) — the two
  role knobs.
- [`x509.rs`](../crates/bv-engine-pki/src/x509.rs) —
  `SubjectInput.email_sans`, emitted in `params_for_subject` (which serves
  `build_leaf`, `build_leaf_from_spki` **and** `build_leaf_csr`).
- [`x509_pqc.rs`](../crates/bv-engine-pki/src/x509_pqc.rs) —
  `build_subject_alt_name` (which `x509_composite.rs` also uses).
- [`csr.rs`](../crates/bv-engine-pki/src/csr.rs) —
  `ParsedCsr.requested_email_sans`, extracted from
  `GeneralName::RFC822Name` instead of being dropped by the catch-all arm.
- [`path_issue.rs`](../crates/bv-engine-pki/src/path_issue.rs),
  [`sign_flow.rs`](../crates/bv-engine-pki/src/sign_flow.rs),
  [`path_csr.rs`](../crates/bv-engine-pki/src/path_csr.rs),
  [`path_sign_request.rs`](../crates/bv-engine-pki/src/path_sign_request.rs)
  — request wiring.
- GUI: [`PkiPage.tsx`](../gui/src/routes/PkiPage.tsx) role form + Issue tab +
  Outgoing CSR tab, [`pki.rs`](../gui/src-tauri/src/commands/pki.rs) command
  surface, [`types.ts`](../gui/src/lib/types.ts).

Coverage:

- `email_san.rs` unit tests — closed by default, structural rejects (no `@`,
  two `@`, empty halves, whitespace, control characters, non-ASCII,
  over-length), allow-list enforcement (case-insensitive, subdomain not
  implied), de-duplication, and a DER round-trip through both encoders.
- [`tests/test_pki_email_sans.rs`](../tests/test_pki_email_sans.rs) —
  end-to-end against a real mount: role closed by default refuses;
  enabled role issues a leaf whose parsed SAN carries the `rfc822Name` and
  whose DNS SAN list is untouched; domain allow-list enforced; a CSR's
  `rfc822Name` survives `sign/:role` and `sign-verbatim` and is refused by a
  role that does not permit it; `csr/generate` puts the address in the
  outgoing CSR; and the ML-DSA path emits the same GeneralName.
