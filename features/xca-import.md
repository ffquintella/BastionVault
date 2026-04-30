# Feature: Import XCA database into the PKI engine (external plugin)

## Summary

Let an operator load an [XCA](https://hohnstaedt.de/xca/) database file
(`*.xdb` — SQLite under the hood) into BastionVault's [PKI engine](pki-secret-engine.md).
This feature ships **as an external plugin** under
[`plugins-ext/bastion-plugin-xca`](../plugins-ext) — *not* compiled
into the host. The plugin sits alongside the existing reference
plugins (`bastion-plugin-totp`, `bastion-plugin-postgres`) and is
loaded at runtime via the existing [plugin system](plugin-system.md).

The host crate gains **zero** code for this feature: no new feature
flag, no new dep, no new HTTP routes. The plugin handles SQLite
parsing, the dual-format password decryption, and the type
translation; the GUI talks to it through the same
`POST /v1/sys/plugins/<name>/invoke` path the other plugins use.

XCA item types map to existing PKI concepts:

| XCA item type | Maps to | Path used |
|---|---|---|
| Certificate (CA) + matching private key | PKI **issuer** | host calls `pki/config/ca/import-bundle` with the PEM pair returned by the plugin |
| Certificate (leaf) | PKI **stored cert** under the parent issuer's namespace | `pki/cert/<serial>` write via existing routes |
| Private key (standalone, no matching cert) | KV blob under `secret/xca-import/<batch-id>/keys/<name>` | regular KV write — out of scope for the PKI engine |
| Certificate Signing Request (CSR) | KV blob under `secret/xca-import/<batch-id>/csrs/<name>` | not auto-converted; operator runs `pki/sign` separately |
| CRL | PKI **CRL state** for the matching issuer (latest CRL pointer + revoked serials) | `pki/issuer/<id>/crl` write |
| Template | KV blob under `secret/xca-import/<batch-id>/templates/<name>` | not auto-converted to a `pki/role` (parameter sets diverge) |

The operator drives the import from a new GUI page (`Settings → PKI → Import XCA`)
that talks to the plugin's invoke endpoint. A preview pass parses
the file and lists what would be imported; a follow-up "run" pass
performs the actual writes. Everything between the GUI and the
host PKI engine flows through the plugin protocol — when the plugin
isn't installed, the menu item simply doesn't render.

## Why an external plugin

- **Keeps the core small.** XCA migration is a one-shot tool for a
  specific class of operator. Bundling `rusqlite` (with bundled
  SQLite) + the dual encryption-format handling into every host
  build pays a permanent cost for an episodic feature. A plugin
  flips that — operators who don't need it never compile or ship it.
- **Decoupled release cadence.** XCA's database schema and
  encryption format have shifted between major releases (1.x → 2.0
  → 2.4). Tracking those shifts inside the host crate would mean a
  BastionVault release every time XCA bumps its format. As a
  plugin, the operator drops in a new `.wasm` / process binary on
  their own schedule.
- **The plugin substrate already supports this.** The
  [plugin system](plugin-system.md) ships both runtimes (WASM +
  out-of-process), and the existing `bastion-plugin-postgres`
  reference plugin is already a working out-of-process plugin
  doing real SQL + dynamic-credential issuance. The XCA importer
  is the same shape and rides on the same plumbing.
- **Plays well with the security model.** The plugin only needs
  capabilities the substrate already exposes: parse a file
  supplied by the operator, decrypt with a password supplied by
  the operator, return structured data. No new host capability is
  introduced; the plugin never touches the barrier directly. All
  PKI writes happen on the host side via existing routes the GUI
  already calls.

## Plugin runtime choice — Process, not WASM

The plugin lives in
[`plugins-ext/bastion-plugin-xca`](../plugins-ext) and uses the
**out-of-process runtime** (the same one
`bastion-plugin-postgres` uses), not WASM:

- **`rusqlite` needs SQLite.** It builds for WASM with the `bundled`
  feature, but the resulting `.wasm` is large (~3 MiB for a
  hello-world plugin once SQLite is linked) and the WASI-FS shim
  doesn't handle SQLite's lock semantics on every host. Process
  runtime side-steps both.
- **File I/O.** The XCA file lives on the operator's disk. Process
  runtime opens the path directly; WASM would need the host to
  read the bytes and pass them through the invoke channel, which
  works but is awkward for files large enough to merit a progress
  bar.
- **Crypto matches the host crate's stack.** The plugin uses the
  same `aes`, `cbc`, `md-5`, `pbkdf2`, `hmac`, `sha2` deps the
  host crate already pulls in transitively. No new audit surface.

The plugin protocol is line-delimited JSON over stdin/stdout — same
as the postgres plugin — so the manifest declares
`runtime = "process"` and the host's existing process supervisor
launches the binary on demand.

## Host-side responsibilities (zero new code)

The host already exposes everything the plugin needs:

- **`POST /v1/sys/plugins`** — operator uploads the packed
  `.bvplugin` artefact. Existing route, no changes.
- **`POST /v1/sys/plugins/xca-import/invoke`** — the plugin's
  endpoint. Body shape is plugin-defined; see *Plugin protocol*
  below.
- **PKI engine routes** — `pki/config/ca/import-bundle`,
  `pki/cert/<serial>`, `pki/issuer/<id>/crl`. The GUI invokes
  these directly with the data the plugin returned. No new PKI
  routes needed.
- **KV engine** — for CSRs / templates / standalone keys. Standard
  `secret/xca-import/<batch-id>/...` writes.

## Plugin protocol

The plugin defines its own request shape on top of the substrate's
`PluginRequest`. The host doesn't interpret these; the GUI
constructs them and the plugin matches on `operation`.

### `operation = "preview"`

```json
{
  "operation": "preview",
  "path": "preview",
  "data": {
    "file": "<base64 .xdb bytes OR absolute file path>",
    "master_password": "<string, optional — only when DB is encrypted>",
    "per_key_passwords": { "<key-name>": "<string>" }
  }
}
```

Returns:

```json
{
  "summary": {
    "format_version": "v2.4|v2.0|v1",
    "issuer_count": 3,
    "leaf_count": 47,
    "csr_count": 2,
    "crl_count": 3,
    "template_count": 5,
    "skipped": ["smartcard:Yubico-PIV-9a", "v1-template:foo"]
  },
  "items": [
    {
      "kind": "issuer",
      "name": "Acme Root CA",
      "serial": "01",
      "subject": "CN=Acme Root,O=Acme",
      "not_before_unix": 1700000000,
      "not_after_unix": 2331720000,
      "key_alg": "RSA-4096",
      "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
      "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
      "key_decryption": "ok|missing_password|wrong_password|unsupported_format"
    },
    { "kind": "leaf", ... },
    { "kind": "csr", ... },
    { "kind": "crl", ... }
  ],
  "decryption_failures": [
    { "name": "API Server Key", "reason": "missing_password" }
  ]
}
```

### `operation = "import"`

The plugin **does not** call PKI routes itself. Instead, it
returns the same payload as `preview` but with a `plan` hint —
the GUI then walks the plan and issues PKI / KV writes via the
existing routes. This keeps the security boundary clean:

- The plugin only ever does parsing + decryption.
- All vault-state mutations go through the host's regular
  policy-checked route surface, audited by the host's audit
  module.

If a future version wants the plugin to drive the writes itself,
the substrate's existing `bv.storage_*` capabilities are scoped to
the plugin's own UUID prefix and would not let the plugin reach
the PKI mount — so the GUI-orchestrated model is also the only
one the substrate currently allows.

### `operation = "validate"`

A cheap pass that opens the SQLite, reads the version, and
returns `{ ok: true|false, format_version, requires_password,
ownpass_keys: ["<name>", ...] }` — the GUI uses this on file
selection so the password fields render only when needed.

## XCA encryption (what the plugin needs to handle)

When the XCA database has a master password set, sensitive blobs
in `private_keys.private` are encrypted. Two formats coexist
across XCA versions; the plugin sniffs the magic and dispatches:

1. **EVP_BytesToKey envelope** (XCA ≤ 2.0) —
   `Salted__` + 8-byte salt + AES-256-CBC ciphertext.
   Key/IV derivation: `EVP_BytesToKey(MD5, salt, password,
   count=1, key_len=32, iv_len=16)`. The OpenSSL `enc -salt`
   default; trivially implementable with `md-5` + `aes` + `cbc`.
2. **PBKDF2-HMAC-SHA512 header** (XCA ≥ 2.4) — header
   `{magic, version, kdf, iter, salt_len, salt, iv_len, iv}`
   followed by AES-256-CBC ciphertext. Iteration count is read
   from the header (typically 200k+).

`private_keys.ownPass` lets an XCA operator pin a per-key
password that overrides the database master password for that one
row. The plugin's `preview` reports which rows have `ownPass` set;
the GUI surfaces a per-key password input for each.

## GUI

`Settings → PKI → Import XCA` — three-step wizard, hidden when the
plugin isn't registered:

1. **Pick file + password.** Native file picker (`*.xdb`), masked
   password input, optional "Per-key passwords" expander populated
   from the plugin's `validate` response.
2. **Review.** Tree view of the parsed items grouped by issuer.
   Per-row checkbox for inclusion; renaming + collision-policy
   dropdown (`Skip` | `Overwrite` | `Rename`).
3. **Run.** Streams progress as the GUI walks the plan and issues
   one PKI / KV write per item. Final summary with a "view in PKI
   page" link.

The GUI checks for the plugin's presence by listing
`/v1/sys/plugins` and looking for `name = "xca-import"`. If
absent, the menu entry under `Settings → PKI` is hidden — no
broken link, no stub page.

## Out of scope (explicit)

- **Round-trip export back to XCA.** One-way migration only.
- **Smart-card-resident keys.** XCA can reference PKCS#11 tokens;
  the actual key material isn't in the database. Surfaced as a
  skip with `smartcard:<reader>` reason.
- **CMC / SCEP enrolment configs (`authority` table).**
- **Auto-converting XCA templates into PKI roles.** Templates land
  in KV; the operator converts by hand if they want to.
- **XCA v1 (XML-shaped payload) databases.** Phase 4 follow-up
  inside the plugin; v2 is the v1 of the plugin's first release.

## Phases (all inside the plugin repo, none in the host)

| # | Title | Notes |
|---|---|---|
| 1 | **Reader skeleton (no decryption) + manifest + invoke wiring** | `bastion-plugin-xca` skeleton, `runtime = "process"`, declares the four operations. Returns plaintext-only fields (cert PEM, public-key DER, CSR PEM, CRL DER, template blob); encrypted private-key rows surfaced with `key_decryption = "missing_password"`. Packaged via `bv-plugin-pack`; `validate` + `preview` work end-to-end against an unencrypted `.xdb` fixture. |
| 2 | **Decryption — both formats** | EVP_BytesToKey + PBKDF2 paths; per-key `ownPass` handling. Round-trip test against an XCA file with both formats present. |
| 3 | **GUI wizard** | `Settings → PKI → Import XCA` page. Plugin presence check, three-step flow, per-item progress as the GUI walks the plan. |
| 4 | **XCA v1 + smart-card surfacing** | XML-shaped v1 reader; smart-card-resident keys reported as skip. |
| 5 | **Hardening + docs** | Fixture-based test matrix (XCA 1.4 / 2.2 / 2.5 fixtures), operator-facing migration guide in the plugin's `README.md`. |

## Open questions

- **Plugin signing.** The substrate's Phase 5.2 ML-DSA-65 publisher
  signature work is now in. Should the XCA plugin be released as a
  signed artefact under a BastionVault-publisher key from day one,
  or stay `accept_unsigned = true` until the operator workflow for
  publisher keys is documented?
- **Where the import-batch state lives.** During an import run the
  GUI walks N items and issues N writes — if the operator closes
  the wizard mid-run, partial state is in the vault. Spec assumes
  this is acceptable (the operator can re-run; collision policy
  picks up where it left off). Worth confirming before we ship.
- **CRL freshness.** Should the importer set the BastionVault CRL
  `next_update` to whatever the imported CRL says (preserving
  XCA's schedule) or to BastionVault's own CRL config? Current
  lean: XCA's value with a banner that says "imported CRL —
  re-sign with `pki/issue` schedule to take over."

## Acceptance criteria

- The XCA plugin builds standalone in
  [`plugins-ext/bastion-plugin-xca`](../plugins-ext), packs to a
  `.bvplugin`, and registers cleanly via the existing
  `POST /v1/sys/plugins` route. **The host crate has no new code,
  no new dep, no new feature flag.**
- An operator can pick a real XCA `.xdb`, type the master password,
  choose which items to import, and end up with new BastionVault
  PKI issuers whose `pki/issue/<role>` flow works against existing
  roles. Skipped items are listed with reasons.
- Uninstalling the plugin removes the menu entry; reinstalling it
  brings it back without restart.
- The import is idempotent in `Skip` collision mode (running twice
  is a no-op).
