# Feature: Import XCA database into the PKI engine (external plugin)

**Status: Done.** External plugin `bastion-plugin-xca` shipped under `plugins-ext/`. Both XCA encryption envelopes supported (EVP_BytesToKey for XCA ≤ 2.0, PBKDF2-HMAC-SHA512 for XCA ≥ 2.4), per-key `ownPass` honoured, GUI wizard live at `Settings → PKI → Import XCA`. The phase table below is preserved for historical reference.

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

**Current state (plugin 0.1.22).** A `private_keys.private` column
holds one of four things, and a single database routinely holds more
than one: XCA re-encrypts a key into the current format only when the
key is touched, so a `.xdb` carried across XCA upgrades accumulates
generations. Only two of the four are self-describing.

1. **Plaintext DER** — no database password. Bare `PrivateKeyInfo`,
   `RSAPrivateKey` or `ECPrivateKey`. Recognised by structure: a DER
   SEQUENCE opening on an INTEGER and spanning the whole blob.
2. **XCA's own envelope** (XCA ≤ 2.4, `pki_evp::encryptKey`) —
   salt/IV (8 bytes) + 3DES-EDE3-CBC ciphertext, PKCS#7-padded. Key
   from `EVP_BytesToKey(SHA-1, salt, password, count=1, key_len=24)`;
   the CBC IV is the same 8 bytes, because XCA passes NULL for the IV
   out-parameter. No magic, no header, no integrity tag — recognised
   by shape alone (8 bytes plus a whole number of DES blocks).
3. **PKCS#8 `EncryptedPrivateKeyInfo`** (XCA ≥ 2.5) — PBES2 with
   PBKDF2 + AES-CBC, written by `i2d_PKCS8PrivateKey_bio`. Salt,
   iteration count, PRF and IV all come from the header.
4. **`Salted__` envelope** — the OpenSSL `enc -salt` default, for
   blobs that reached the column by way of the OpenSSL CLI.
   `EVP_BytesToKey(MD5, salt, password, count=1, 32, 16)`.

A blob matching none of the four is **refused**, with the length and
first byte in the message. It is never passed through as if it were
plaintext: doing that is what put raw 3DES ciphertext in front of the
host's `pki/keys/import` and made a decode failure look like a wrong
password. Token-backed (smartcard) rows land here legitimately —
their key material is not in the file.

None of the envelopes carries a MAC, so a wrong password can clear
PKCS#7 unpadding by chance (~1 in 256). Every decrypt is therefore
followed by a DER shape check on the plaintext, and a failure is
reported as a wrong password rather than handed on.

`private_keys.ownPass` is an INTEGER holding XCA's
`pki_key::passType`: `ptCommon` (0, database password), `ptPrivate`
(1, a password of this key's own), `ptBogus` (2, encrypted under the
literal string `"Bogus"`), `ptPin` (3, token-backed). The plugin's
`preview` reports the `ptPrivate` rows; the GUI surfaces a per-key
password input for each.

## GUI

`Settings → PKI → Import XCA` — four-step wizard, hidden when the
plugin isn't registered:

1. **Pick file + password.** Native file picker (`*.xdb`), masked
   database-password input. The file is read locally and shipped to
   the plugin inline as `file_b64`, so the same flow works whether the
   vault is embedded or remote.
2. **Per-key passwords.** Shown after the first preview whenever the
   response carries keys with `has_own_pass` (XCA's `ptPrivate`) or
   keys that failed on a password. Implemented — see below.
3. **Review.** Table of the parsed items with a per-row **Import**
   checkbox, the plugin's issuer/leaf routing, and the key state of
   each row. Renaming + collision policy are still to come; today the
   importer auto-suffixes on name collision.
4. **Run.** Walks the selection and issues one PKI / KV write per
   item, then reports imported / skipped / failed counts.

### Per-key passwords (`ptPrivate` keys)

The database password does not open a `ptPrivate` key — each has one
of its own. This is the majority case on real files, not a corner: 443
of 551 keys in one production `.xdb` and 172 of 194 in another. Before
plugin 0.1.22 the flag was never reported (the INTEGER `ownPass`
column was read as `Option<String>` and the error swallowed), so the
GUI could not have asked.

The **Keys with their own password** section renders after the first
preview and holds:

- One masked field per key, locked keys sorted first, each labelled
  with the key's name and a badge carrying its decrypt state
  (`locked — wrong_password`, `locked — missing_password`, or
  `unlocked`). `unsupported` is not a password problem and gets no
  field.
- A **password for all remaining locked keys** field with an "Apply to
  N remaining" button — the realistic case is a batch of keys imported
  from PFX files in one delivery, all sharing a password. It fills
  every still-locked key and leaves the already-open ones untouched.
- **Re-preview with passwords**, which re-invokes `preview` with
  `per_key_passwords` (keyed by item name) and then reports which keys
  moved from locked to decrypted and how many remain, so the operator
  converges batch by batch instead of diffing the table by eye.
- **Clear passwords**, which drops everything typed so far.

The import table states the consequence of leaving a key locked
rather than letting it fail at Apply time: a locked key is flagged and
left unchecked (skip), a certificate whose paired key is locked is
flagged **key locked — cert only** (it still imports, without the
key), and a CA in the same state is flagged **key locked — will be
skipped**, because an issuer without its key cannot be installed.
Each flag carries an "Enter password" link that focuses that key's
field.

**Handling of the passwords themselves.** They live in React component
state and nowhere else: not persisted, not logged, not put in a store,
and sent only in the `preview` invocation. They are dropped when the
preview is cancelled, when a different file is picked, and when an
import completes. The fields inherit the GUI's global autofill/
spellcheck opt-out, so the WebView never caches them either.

Regression coverage: `gui/src/test/pkiXcaPerKeyPasswords.test.tsx`.

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
