# Sample PKI policies

Three example Vault-style policies for separating concerns on a PKI mount:

| File | Role | Can do | Cannot do |
|------|------|--------|-----------|
| [`pki-readonly.hcl`](pki-readonly.hcl) | View-only | Read certs, issuers, roles, CRL. | Issue, sign, revoke, **export**. |
| [`pki-issuer.hcl`](pki-issuer.hcl) | Issue + revoke | Everything `pki-readonly` does, plus `pki/issue/<role>`, `pki/sign/<role>`, `pki/sign-verbatim`, `pki/revoke`, `pki/csr/*`. | **Export** cert / key bytes. |
| [`pki-exporter.hcl`](pki-exporter.hcl) | Pull cert + key out | Everything `pki-readonly` does, plus `pki/cert/+/export` and `pki/issuer/+/export`. | Issue / revoke. |

These compose. A typical operator setup:

* Auditor → `pki-readonly`
* CI service account → `pki-issuer`
* Helpdesk / tooling that re-installs certs on hosts → `pki-exporter`

## Defence-in-depth gates

The export endpoints layer **three** independent checks. The policy ACL
in this directory is the outermost — once the ACL admits the caller,
the host still enforces:

1. **`KeyEntry.exportable`** — pinned at managed-key create / import
   time, **read-only thereafter**. Even root cannot flip it. If the
   bound key was minted `exportable=false`, the export refuses
   `include_private_key=true`. The cert (public material) is always
   exportable.

2. **Issuer rule** — `pki/issuer/<ref>/export` never accepts
   `include_private_key` at all. Issuer private keys never leave the
   vault, regardless of policy.

3. **Backup mode** — `mode=backup` bypasses (1) so an operator can
   take an encrypted full-vault backup, but only when paired with an
   encrypted format (PKCS#12 — landing in a follow-up). PEM / PKCS#7
   in backup mode are rejected.

## Default `exportable` values

The flag defaults differ by call site to balance compatibility with
the safer-by-default principle:

| Endpoint | Default `exportable` | Rationale |
|----------|----------------------|-----------|
| `pki/keys/generate` | `false` | Operator opts in explicitly when they want a re-extractable key. |
| `pki/keys/import` | `false` | Same — imports default to non-exportable. |
| `pki/csr/generate` | `false` | The key stays in the vault while the external CA signs the CSR; export is rare here. |
| `pki/issue/<role>` | `true` (compat) | The leaf is meant to be handed to the requester; the response already carries the PEM in the legacy flow. |

The flag is captured at the moment a managed-key entry is persisted
and stays read-only thereafter. There's no API to flip it after the
fact — the operator must mint a fresh key (which gets a new `key_id`)
and re-issue against the new key.
