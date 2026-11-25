# Signing the executables inside the installers

`sign-exe.sh` signs `bvault` and the GUI app with a certificate that stays on
your machine. Nothing about it is in the Makefile or in git.

```sh
make package exe-sign-setup   # first run: asks for the files, saves the paths
make package exe-sign         # build bvault and write a signed copy to target/signed/bin/
make package exe-verify
make package cli-pkg          # macOS CLI .pkg with the signed binary inside
```

The installer targets (`cli-deb`, `cli-rpm`, `cli-msi`, `cli-nupkg`, `cli-pkg`,
`gui-pkg`) sign automatically when a configuration exists. If none exists and
you are on a terminal, the first of them asks for the files. `SIGN=0` skips
signing for one run. With no terminal and no config (CI) it skips with a note.

## Configuration

`${BV_SIGN_CONFIG:-~/.config/bastionvault/signing.conf}`, mode 600. It holds
paths only: no key material, no passphrases. Answer blank to both questions to
disable signing; `REDO=1` re-asks.

| Key | Meaning |
|---|---|
| `CLASSICAL_CERT` / `_KEY` / `_CHAIN` | RSA, ECDSA or Ed25519 cert + key (PEM), or a `.pfx`/`.p12` (no key file) |
| `PQC_CERT` / `_KEY` / `_CHAIN` | ML-DSA-44/65/87 or SLH-DSA cert + key (PEM), OpenSSL >= 3.5 |
| `TIMESTAMP_URL` | RFC 3161 server (Authenticode, codesign); `BV_SIGN_NO_TS=1` disables |
| `OPENSSL` | OpenSSL to use; the first one that supports ML-DSA is picked otherwise |

Encrypted keys: set `BV_SIGN_CLASSICAL_PASS` / `BV_SIGN_PQC_PASS`, or type the
passphrase at the silent prompt. It is never stored.

## ML-KEM

An ML-KEM certificate is refused. ML-KEM is a key-encapsulation scheme; its
key encrypts and cannot sign. Use the ML-DSA or SLH-DSA certificate of the
same hierarchy.

## What gets signed, and where it travels

| Binary | Classical identity | PQC identity |
|---|---|---|
| macOS Mach-O, `.app` | embedded `codesign` | detached `.pqc.p7s` (a `.app`: over a SHA-256 `.manifest`) |
| Windows `.exe` | embedded Authenticode (`osslsigncode`) | detached `.pqc.p7s` |
| Linux ELF | detached `.p7s` | detached `.pqc.p7s` |

No operating-system loader checks ML-DSA, so a PQC signature is always a
detached CMS file, verified with `openssl cms -verify`. Where the sidecars go:

- macOS CLI `.pkg`: `/usr/local/share/bastionvault/signatures/`
- Linux `.deb` / `.rpm`: `/usr/share/bastionvault/signatures/`
- Windows `.nupkg`: next to `bvault.exe` in `tools/`
- Windows CLI `.msi` and the macOS GUI `.pkg`: beside the installer (`target/msi/`, `target/pkg/`)

Verify a shipped signature by hand:

```sh
openssl cms -verify -binary -inform DER -in bvault.pqc.p7s -content bvault \
    -CAfile ca-or-signer.pem -purpose any -partial_chain -out /dev/null
```

## Not covered

- The GUI Windows and Linux binaries are built inside Tauri's Docker/VM
  bundlers, so only the finished installers are signed (`make package sign`,
  which reads the same config for Authenticode).
- The deb/rpm variants and the `osslsigncode` path were written but not run on
  this machine (no `cargo-deb`, `cargo-generate-rpm` or `osslsigncode`).
